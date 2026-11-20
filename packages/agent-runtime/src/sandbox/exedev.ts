import { createHash, randomBytes } from "node:crypto";
import { posix } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  accountHash,
  classifyFailure,
  discardFailedCreate,
  SANDBOX_PREVIEW_RENEWAL_MS,
  SANDBOX_PROVIDER_PROFILES,
  SandboxProviderError,
  shellQuote,
  terminated,
  validateLifetime,
  validatePort,
  type SandboxFailureCode,
  type SandboxProviderInfo,
  type SandboxTransport,
} from "./types";

const profile = SANDBOX_PROVIDER_PROFILES.exedev;
export const DEFAULT_EXEDEV_SANDBOX_IMAGE = "node:22-bookworm";
const NAME_PREFIX = "gitterm-sbx-";
const MAX_EXEC_BODY_BYTES = 64_000;
const PART_BYTES = 45 * 1024;
const UPLOAD_CONCURRENCY = 8;
const REQUEST_DEADLINE_MS = 120_000;
const CLEANUP_DEADLINE_MS = 10_000;
const DETACHED_OUTPUT_BYTES = 1024 * 1024;
const BOOT_ID = "/proc/sys/kernel/random/boot_id";
const READ_CHUNK_BYTES = 4 * 1024 * 1024;

type VmList = { vms?: Array<{ vm_name: string; status?: string }> };
const execClock = {
  now: () => Date.now(),
  timer(ms: number, fire: () => void) {
    const handle = setTimeout(fire, ms);
    return () => clearTimeout(handle);
  },
  deadline: (ms: number) => AbortSignal.timeout(ms),
};

class ExecFailure extends SandboxProviderError {
  constructor(
    code: SandboxFailureCode,
    message: string,
    readonly retryable: boolean,
  ) {
    super(code, message);
  }
}

const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const base64 = (data: Uint8Array) =>
  Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64");
const backoff = (attempt: number) => Math.random() * (1_000 * 2 ** attempt);

function checkExecBody(command: string) {
  if (Buffer.byteLength(command) > MAX_EXEC_BODY_BYTES)
    throw new SandboxProviderError(
      "provider",
      `exe.dev command exceeds ${MAX_EXEC_BODY_BYTES} bytes.`,
    );
}

function parseRetryAfter(value: string | null, now: number) {
  const header = value?.trim() ?? "";
  const ms = /^\d+$/.test(header) ? Number(header) * 1_000 : Date.parse(header) - now;
  return Number.isFinite(ms) ? Math.max(0, ms) : undefined;
}

function checkUpload(result: { exitCode: number; stderr: string }) {
  if (result.exitCode === 0) return;
  if (result.exitCode === 10 || result.stderr.includes("No space left"))
    throw new SandboxProviderError("provider", "Not enough disk in the sandbox for the upload.");
  if (result.exitCode === 8)
    throw new SandboxProviderError("provider", "The upload directory is missing in the VM.");
  const tail = result.stderr.trim().slice(-400);
  throw new ExecFailure(
    [124, 137].includes(result.exitCode) ? "timeout" : "provider",
    `Could not upload the file to the VM (exit ${result.exitCode})${tail ? `: ${tail}` : "."}`,
    [9, 124, 137].includes(result.exitCode),
  );
}

function execLimiter(clock: typeof execClock) {
  let rate = 0;
  let activeParts = 0;
  let latency = 60;
  let successes = 0;
  let generation = 0;
  let refusals = 0;
  let cooldown = 0;
  let nextRequest = 0;
  const waiters = new Set<() => void>();
  return {
    async acquire(part: boolean, signal: AbortSignal) {
      for (;;) {
        signal.throwIfAborted();
        const now = clock.now();
        const wait = Math.max(cooldown, nextRequest) - now;
        const limit = rate
          ? Math.min(UPLOAD_CONCURRENCY, Math.ceil((rate * latency) / 1000) + 1)
          : UPLOAD_CONCURRENCY;
        if (wait <= 0 && (!part || activeParts < limit)) {
          // One token at a time after a 429; time spent idle never saves up another burst.
          if (rate) nextRequest = now + 1_000 / rate;
          if (part) activeParts++;
          return { generation, startedAt: now };
        }
        await new Promise<void>((resolve) => {
          const wake = () => {
            cancel?.();
            signal.removeEventListener("abort", wake);
            waiters.delete(wake);
            resolve();
          };
          const cancel = wait > 0 ? clock.timer(Math.min(wait, 2 ** 31 - 1), wake) : undefined;
          waiters.add(wake);
          signal.addEventListener("abort", wake, { once: true });
        });
      }
    },
    release(part: boolean) {
      if (part) {
        activeParts--;
        for (const wake of waiters) wake();
      }
    },
    succeeded(admission: { generation: number; startedAt: number }, part: boolean) {
      if (admission.generation !== generation) return;
      if (part) latency = latency * 0.9 + (clock.now() - admission.startedAt) * 0.1;
      refusals = 0;
      if (rate && ++successes === 50) {
        rate = Math.min(20, rate + 1);
        successes = 0;
      }
    },
    failed(admission: { generation: number }) {
      if (admission.generation === generation) successes = 0;
    },
    refused(retryAfter: number | undefined) {
      generation++;
      successes = 0;
      rate = rate ? Math.max(2, rate / 2) : 8;
      const now = clock.now();
      const cap = 500 * 2 ** Math.min(refusals++, 4);
      cooldown = Math.max(cooldown, now + (retryAfter ?? cap * (0.5 + Math.random() / 2)));
      nextRequest = Math.max(nextRequest, now + 1_000 / rate);
    },
  };
}

// The lobby lexes the request first, then the VM shell parses its single command argument.
function sshBody(id: string, command: string, seconds: number) {
  const remote = `timeout -k 3 ${seconds} bash -c ${shellQuote(command)}`;
  return `ssh ${id} ${shellQuote(remote)}`;
}

/**
 * An exe.dev VM from a plain image (the default `exeuntu` image ships coding agents).
 * exe.dev has no lifetime or auto-delete, so a VM runs until destroyed. The exec API
 * allows 30 s and 64 KB per request: jobs launch detached and uploads are chunked.
 */
export function createExeDevSandboxTransport(
  config: {
    apiKey: string;
    image?: string;
    /** Used when no machine profile is given, as exe.dev's `new` flags take them. */
    cpu?: number;
    memory?: string;
    disk?: string;
  },
  clock = execClock,
): SandboxTransport {
  if (!config.apiKey?.trim()) throw new SandboxProviderError("auth", "exe.dev token is empty.");
  const accessKeys = new Map<string, { token: string; expiresAt?: number }>();
  const limiter = execLimiter(clock);

  async function request(
    command: string,
    action: string,
    accept = "text/plain",
    timeoutSeconds = 25,
    signal = clock.deadline(REQUEST_DEADLINE_MS),
    part = false,
  ) {
    checkExecBody(command);
    for (;;) {
      let admission: Awaited<ReturnType<typeof limiter.acquire>> | undefined;
      try {
        admission = await limiter.acquire(part, signal);
        signal.throwIfAborted();
        const timeout = clock.deadline((timeoutSeconds + 20) * 1000);
        const response = await fetch("https://exe.dev/exec", {
          method: "POST",
          headers: {
            authorization: `Bearer ${config.apiKey}`,
            "content-type": "text/plain",
            accept,
          },
          body: command,
          signal: AbortSignal.any([signal, timeout]),
        });
        // A 429 refused the command before execution. Only this layer replays it.
        if (response.status === 429) {
          limiter.refused(parseRetryAfter(response.headers.get("retry-after"), clock.now()));
          void response.body?.cancel().catch(() => {});
          continue;
        }
        const text = await response.text();
        signal.throwIfAborted();
        if (response.ok) limiter.succeeded(admission, part);
        else limiter.failed(admission);
        return { status: response.status, ok: response.ok, text };
      } catch (error) {
        if (signal.aborted)
          throw new SandboxProviderError("timeout", `exe.dev timed out while trying to ${action}.`);
        if (admission) limiter.failed(admission);
        const failure = classifyFailure("exe.dev", error, action);
        throw new ExecFailure(failure.code, failure.message, true);
      } finally {
        if (admission) limiter.release(part);
      }
    }
  }

  function checked({ status, ok, text }: Awaited<ReturnType<typeof request>>, action: string) {
    if (status === 401 || status === 403)
      throw new SandboxProviderError(
        "auth",
        `exe.dev rejected the token while trying to ${action}. Sandbox tokens need cmds new, ls, ssh, pause, resume, and rm. Private previews also need the exact subcommand "ssh-key generate-api-key".`,
      );
    if (!ok) {
      const failure =
        status === 504
          ? new SandboxProviderError("timeout", `exe.dev timed out while trying to ${action}.`)
          : classifyFailure(
              "exe.dev",
              Object.assign(new Error(`${status} ${text.slice(0, 200)}`), { status }),
              action,
            );
      throw new ExecFailure(failure.code, failure.message, status >= 500 && status < 600);
    }
    return text;
  }

  async function exec(command: string, action: string, signal?: AbortSignal): Promise<string> {
    return checked(await request(command, action, undefined, undefined, signal), action);
  }

  async function mintPreviewKey(id: string) {
    const action = "create a preview key";
    // Labels must be unique even across processes. Keep the old long-lived behavior if allowed.
    const label = `gitterm-sandbox-${randomBytes(8).toString("hex")}`;
    const command = `ssh-key generate-api-key --vm=${id} --label=${label}`;
    const outlivesParent = ({ status, text }: Awaited<ReturnType<typeof request>>) =>
      status === 422 && text.includes("Cannot create a new key that outlives");
    let result = await request(`${command} --exp=never`, action);
    const shortLived = outlivesParent(result);
    if (shortLived) {
      result = await request(`${command} --exp=1h`, action);
      if (outlivesParent(result))
        throw new SandboxProviderError(
          "auth",
          "exe.dev needs a sandbox token with at least one hour remaining to create a private preview key.",
        );
    }
    const text = checked(result, action);
    let token: string | undefined;
    let expiresAt: number | undefined;
    try {
      const data = JSON.parse(text) as { token?: string; expires_at?: string } | null;
      token = data?.token;
      if (shortLived) expiresAt = Date.parse(data?.expires_at ?? "");
    } catch {
      // Don't include a response that might contain a credential in an error.
    }
    if (typeof token !== "string" || !token)
      throw new SandboxProviderError("provider", "exe.dev did not return a VM access key.");
    if (shortLived && !Number.isFinite(expiresAt))
      throw new SandboxProviderError("provider", "exe.dev did not report the preview key expiry.");
    return { token, expiresAt };
  }

  const parseList = (text: string): VmList => {
    try {
      return JSON.parse(text) as VmList;
    } catch {
      return {};
    }
  };

  const infoFrom = (name: string, status: string | undefined): SandboxProviderInfo => {
    const match = new RegExp(`^${NAME_PREFIX}([a-f0-9]{10})-`).exec(name);
    return {
      id: name,
      state:
        status === "running"
          ? "running"
          : status === "paused"
            ? "paused"
            : status === "creating"
              ? "pending"
              : "terminated",
      labels: match ? { gitterm_account_hash: match[1]!, gitterm_workload: "sandbox" } : {},
      startedAt: null,
      expiresAt: null,
    };
  };

  async function info(id: string, signal?: AbortSignal): Promise<SandboxProviderInfo> {
    if (!/^[a-z0-9-]+$/.test(id)) throw new Error("Invalid exe.dev VM name");
    try {
      const vm = parseList(await exec(`ls ${id} --json`, "read the sandbox", signal)).vms?.find(
        (item) => item.vm_name === id,
      );
      return vm ? infoFrom(id, vm.status) : terminated(id);
    } catch (error) {
      if (error instanceof SandboxProviderError && error.code === "not_found")
        return terminated(id);
      throw error;
    }
  }

  async function ssh(
    id: string,
    command: string,
    timeoutMs = 25_000,
    signal?: AbortSignal,
    part = false,
  ) {
    const seconds = Math.max(1, Math.min(25, Math.floor(timeoutMs / 1000)));
    const action = "run a command";
    const text = checked(
      await request(
        sshBody(id, command, seconds),
        action,
        "application/x-ndjson",
        seconds,
        signal,
        part,
      ),
      action,
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    // fetch cannot read exe.dev's X-Exe-Exit trailer; NDJSON carries the exit status in-band.
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      let frame: { stdout?: string; stderr?: string; exit_code?: number; error?: string } | null;
      try {
        frame = JSON.parse(line);
      } catch {
        throw new ExecFailure("provider", "exe.dev returned invalid command output.", true);
      }
      if (typeof frame?.error === "string")
        throw new ExecFailure(
          "provider",
          `exe.dev could not run the command: ${frame.error}`,
          true,
        );
      if (typeof frame?.stdout === "string") stdout.push(Buffer.from(frame.stdout, "base64"));
      if (typeof frame?.stderr === "string") stderr.push(Buffer.from(frame.stderr, "base64"));
      const exitCode = frame?.exit_code;
      if (typeof exitCode === "number" && Number.isInteger(exitCode)) {
        return {
          exitCode,
          stdout: Buffer.concat(stdout).toString(),
          stderr: Buffer.concat(stderr).toString(),
        };
      }
    }
    throw new ExecFailure("provider", "exe.dev did not report the command's exit code.", true);
  }

  async function running(id: string, signal?: AbortSignal) {
    const current = await info(id, signal);
    if (current.state !== "running")
      throw new SandboxProviderError("not_found", `The exe.dev VM is ${current.state}.`);
  }

  async function runDetached(
    id: string,
    command: string,
    timeoutMs: number,
    deadline: AbortSignal,
  ) {
    const dir = `D="\${TMPDIR:-/tmp}/gitterm-run-${randomBytes(8).toString("hex")}"`;
    const bootMatches = `[ "$(cat "$D/boot" 2>/dev/null)" = "$(cat ${BOOT_ID})" ]`;
    const readPid = `read -r pid < "$D/pid" && [[ "$pid" =~ ^[1-9][0-9]*$ ]]`;
    const wait = (remove: boolean) => `
      end=$((SECONDS + 20))
      while ${bootMatches}; do
        if [ -f "$D/exit" ]; then
          printf 'done\\n%s\\n' "$(cat "$D/exit")"
          for stream in out err; do
            printf '%s\\n' "$(wc -c < "$D/$stream")"
            tail -c ${DETACHED_OUTPUT_BYTES} -- "$D/$stream" | base64 -w0
            printf '\\n'
          done
          ${remove ? 'rm -rf -- "$D"' : ":"}
          exit 0
        fi
        if [ -f "$D/pid" ] && ! (${readPid} && kill -0 "$pid" 2>/dev/null); then
          [ -f "$D/exit" ] && continue
          break
        fi
        if [ "$SECONDS" -ge "$end" ]; then
          if [ -f "$D/pid" ]; then echo running; else echo lost; fi
          exit 0
        fi
        sleep 0.25
      done
      echo lost`;
    const reap = (terminate: boolean) =>
      ssh(
        id,
        `${dir}
        ${
          terminate
            ? `if [ ! -f "$D/exit" ] && ${bootMatches} && [ -f "$D/pid" ] && ${readPid}; then
                kill -TERM -- "-$pid" 2>/dev/null || :
              fi`
            : ""
        }
        rm -rf -- "$D"`,
        10_000,
        clock.deadline(CLEANUP_DEADLINE_MS),
      ).catch(() => {});
    const detached = `timeout -k 5 ${Math.ceil(timeoutMs / 1000)} bash cmd >out 2>err &
      pid=$!
      printf '%s\\n' "$pid" >pid.tmp && mv -f pid.tmp pid
      wait "$pid"
      printf '%s\\n' "$?" >exit.tmp && mv -f exit.tmp exit`;
    const launch = `
      set -e
      ${dir}
      find "\${TMPDIR:-/tmp}" -maxdepth 1 -regextype posix-extended -type d \\
        -regex '.*/gitterm-run-[0-9a-f]{16}' -mmin +60 -exec rm -rf -- {} +
      mkdir -m 700 -- "$D"
      umask 077
      printf '%s' '${Buffer.from(command).toString("base64")}' | base64 -d > "$D/cmd"
      cat ${BOOT_ID} > "$D/boot"
      (cd -- "$D" && setsid nohup sh -c ${shellQuote(detached)} </dev/null >/dev/null 2>&1 &)
      ${wait(true)}`;
    checkExecBody(sshBody(id, launch, 25));
    try {
      let result = await ssh(id, launch, 25_000, deadline);
      let polled = false;
      for (;;) {
        deadline.throwIfAborted();
        const [state, code, outSize, out, errSize, err] = result.stdout.split("\n");
        if (result.exitCode === 0 && state === "done") {
          if (
            !/^\d+$/.test(code ?? "") ||
            !/^\d+$/.test(outSize ?? "") ||
            !/^\d+$/.test(errSize ?? "") ||
            out === undefined ||
            err === undefined
          )
            throw new SandboxProviderError("provider", "exe.dev returned invalid detached output.");
          const output = (encoded: string, size: string) =>
            (Number(size) > DETACHED_OUTPUT_BYTES ? "[truncated to the last 1 MiB]\n" : "") +
            Buffer.from(encoded, "base64").toString();
          // A poll never consumes the result: its response might be lost and need replaying.
          if (polled) await reap(false);
          return {
            exitCode: Number(code),
            stdout: output(out, outSize!),
            stderr: output(err, errSize!),
          };
        }
        if (result.exitCode === 0 && state === "lost")
          throw new SandboxProviderError("provider", "exe.dev lost the detached command.");
        if (result.exitCode !== 0 || state !== "running")
          throw new SandboxProviderError(
            "provider",
            `exe.dev could not track the detached command (exit ${result.exitCode}): ${result.stderr.trim().slice(-400)}`,
          );
        for (let attempt = 0; ; attempt++) {
          try {
            result = await ssh(id, `${dir}\n${wait(false)}`, 25_000, deadline);
            break;
          } catch (error) {
            if (!(error instanceof ExecFailure && error.retryable) || attempt === 3) throw error;
            await delay(backoff(attempt), undefined, { signal: deadline });
          }
        }
        polled = true;
      }
    } catch (error) {
      await reap(true);
      if (deadline.aborted)
        throw new SandboxProviderError("timeout", "Timed out waiting for the exe.dev command.");
      throw error;
    }
  }

  async function uploadParts(
    id: string,
    dir: string,
    data: Uint8Array,
    count: number,
    deadline: AbortSignal,
    uploaded: (bytes: number) => void,
  ) {
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, deadline]);
    let next = 0;
    let remainingRetries = Math.max(8, Math.floor(count * 0.02));
    async function worker() {
      while (next < count) {
        const index = next++;
        const part = data.subarray(index * PART_BYTES, (index + 1) * PART_BYTES);
        const hash = sha256(part);
        const name = `p${String(index).padStart(6, "0")}`;
        for (let attempt = 0; ; attempt++) {
          try {
            const temp = `t${index}.${attempt}`;
            checkUpload(
              await ssh(
                id,
                `cd -- ${dir} || exit 8
                trap 'rm -f -- ${temp}' EXIT
                printf '%s' '${base64(part)}' | base64 -d > ${temp} || exit 1
                [ "$(sha256sum < ${temp} | cut -d' ' -f1)" = ${hash} ] || exit 9
                mv -fT -- ${temp} ${name}`,
                10_000,
                signal,
                true,
              ),
            );
            uploaded(part.byteLength);
            break;
          } catch (error) {
            signal.throwIfAborted();
            if (
              !(error instanceof ExecFailure && error.retryable) ||
              attempt === 3 ||
              remainingRetries === 0
            ) {
              controller.abort(error);
              return;
            }
            remainingRetries--;
            const pause = backoff(attempt);
            if (pause) await delay(pause, undefined, { signal });
          }
        }
      }
    }
    // The first failure owns cancellation; wait for every worker before removing staging files.
    await Promise.all(
      Array.from({ length: Math.min(count, UPLOAD_CONCURRENCY) }, () =>
        worker().catch((error) => controller.abort(error)),
      ),
    );
    signal.throwIfAborted();
  }

  return {
    provider: "exedev",
    ...profile,

    async create(input) {
      validateLifetime(input.timeoutMs, profile.capabilities.maxLifetimeMs);
      const account = input.labels.gitterm_account ?? input.labels.gitterm_workspace ?? "managed";
      const name = `${NAME_PREFIX}${accountHash(account)}-${randomBytes(4).toString("hex")}`;
      const machine = input.machine ?? config;
      const size = (["cpu", "memory", "disk"] as const)
        .filter((key) => machine[key])
        .map((key) => ` --${key}=${shellQuote(String(machine[key]))}`)
        .join("");
      await exec(
        `new --name=${name} --no-email --image=${shellQuote(input.template ?? config.image ?? DEFAULT_EXEDEV_SANDBOX_IMAGE)}${size} --json`,
        "create a sandbox",
      );
      try {
        const deadline = clock.deadline(REQUEST_DEADLINE_MS);
        while ((await info(name, deadline)).state !== "running")
          await delay(1_000, undefined, { signal: deadline });
        const check = await ssh(name, "true", 25_000, deadline);
        if (check.exitCode !== 0) throw new Error("VM did not run a command");
        return await info(name, deadline);
      } catch (error) {
        return discardFailedCreate(() => exec(`rm ${name}`, "delete the sandbox"), name, error);
      }
    },

    info,

    async list(labels) {
      const wanted = labels.gitterm_account ? accountHash(labels.gitterm_account) : undefined;
      return (parseList(await exec("ls --json", "list sandboxes")).vms ?? [])
        .filter((vm) => vm.vm_name.startsWith(wanted ? `${NAME_PREFIX}${wanted}-` : NAME_PREFIX))
        .map((vm) => infoFrom(vm.vm_name, vm.status))
        .filter((item) => item.state !== "terminated");
    },

    async destroy(id) {
      accessKeys.delete(id);
      const deadline = clock.deadline(REQUEST_DEADLINE_MS);
      if ((await info(id, deadline)).state === "terminated") return;
      await exec(`rm ${id}`, "delete the sandbox", deadline);
    },

    async pause(id) {
      await exec(`pause ${id}`, "pause the sandbox");
    },

    async resume(id) {
      await exec(`resume ${id}`, "resume the sandbox");
    },

    async run(id, command, options = {}) {
      const vmTimeout = options.timeoutMs ?? 25_000;
      const deadline = clock.deadline(
        vmTimeout > 30_000 ? vmTimeout + 20_000 : REQUEST_DEADLINE_MS,
      );
      await running(id, deadline);
      const exports = Object.entries(options.env ?? {})
        .map(([key, value]) => {
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
            throw new Error(`Invalid variable name: ${key}`);
          return `export ${key}=${shellQuote(value)}; `;
        })
        .join("");
      const cd = options.cwd ? `cd ${shellQuote(options.cwd)} && ` : "";
      if (vmTimeout > 30_000)
        return runDetached(id, `${exports}${cd}${command}`, vmTimeout, deadline);
      return ssh(id, `${exports}${cd}${command}`, vmTimeout, deadline);
    },

    async writeFile(id, path, data) {
      const deadline = clock.deadline(120_000 + Math.ceil((data.byteLength * 1000) / (64 * 1024)));
      const file = path.startsWith("/") ? path : `./${path}`;
      const target = shellQuote(file);
      const parent = shellQuote(posix.dirname(file));
      const nonce = randomBytes(8).toString("hex");
      const temp = shellQuote(`${file}.gitterm-${nonce}.tmp`);
      const verify = `[ "$(sha256sum < "$T" | cut -d' ' -f1)" = ${sha256(data)} ]`;
      const stage = `T=${temp}; trap 'rm -f -- "$T"' EXIT`;
      const count = Math.ceil(data.byteLength / PART_BYTES);
      const dir = shellQuote(`${file}.gitterm-parts-${nonce}`);
      let staged = false;
      let bytesDone = 0;
      try {
        await running(id, deadline);
        staged = true;
        if (count <= 1) {
          checkUpload(
            await ssh(
              id,
              `
          set -e
          mkdir -p -- ${parent}
          ${stage}
          printf '%s' '${base64(data)}' | base64 -d > "$T"
          ${verify} || exit 9
          mv -fT -- "$T" ${target}`,
              25_000,
              deadline,
            ),
          );
          return;
        }
        checkUpload(
          await ssh(
            id,
            `
          set -eo pipefail
          mkdir -p -- ${parent}
          find ${parent} -maxdepth 1 -regextype posix-extended -type d \\
            -regex '.*\\.gitterm-parts-[0-9a-f]{16}' -mmin +60 -exec rm -rf -- {} +
          space=$(df -Pk -- ${parent} | awk 'NR == 2 { print $4 }')
          [[ "$space" =~ ^[0-9]+$ ]] || exit 1
          [ "$space" -ge ${Math.ceil((2 * data.byteLength + 64 * 1024 * 1024) / 1024)} ] || exit 10
           mkdir -m 700 -- ${dir}`,
            25_000,
            deadline,
          ),
        );
        await uploadParts(id, dir, data, count, deadline, (bytes) => {
          bytesDone += bytes;
        });
        const assemble = `
          set -e
          export LC_ALL=C
          U=${dir}
          ${stage}
          (cd -- "$U" || exit 8
            set -- p[0-9]*
            [ "$#" -eq ${count} ] || exit 9
            printf '%s\\0' "$@" | xargs -0 cat --) > "$T"
          [ "$(wc -c < "$T")" -eq ${data.byteLength} ] && ${verify} || exit 9
          mv -fT -- "$T" ${target}
          rm -rf -- "$U"`;
        checkUpload(
          data.byteLength > 256 * 1024 * 1024
            ? await runDetached(
                id,
                assemble,
                120_000,
                AbortSignal.any([deadline, clock.deadline(140_000)]),
              )
            : await ssh(id, assemble, 25_000, deadline),
        );
      } catch (error) {
        const timedOut = deadline.aborted;
        if (staged && (count > 1 || timedOut))
          await ssh(
            id,
            `rm -rf -- ${dir} ${temp}`,
            10_000,
            clock.deadline(CLEANUP_DEADLINE_MS),
          ).catch(() => {});
        if (timedOut)
          throw new SandboxProviderError(
            "timeout",
            `exe.dev upload timed out (${bytesDone}/${data.byteLength} bytes uploaded).`,
          );
        throw error;
      }
    },

    async readFile(id, path) {
      await running(id);
      const size = await ssh(id, `wc -c < ${shellQuote(path)}`);
      if (size.exitCode !== 0)
        throw new SandboxProviderError("not_found", `No file at ${path} in the VM.`);
      const total = Number(size.stdout.trim());
      const chunks: Buffer[] = [];
      for (let block = 0; block * READ_CHUNK_BYTES < total; block++) {
        const part = await ssh(
          id,
          `dd if=${shellQuote(path)} bs=${READ_CHUNK_BYTES} skip=${block} count=1 2>/dev/null | base64 -w0`,
        );
        if (part.exitCode !== 0)
          throw new SandboxProviderError("provider", "Could not download the file from the VM.");
        chunks.push(Buffer.from(part.stdout.trim(), "base64"));
      }
      return new Uint8Array(Buffer.concat(chunks));
    },

    async preview(id, port) {
      validatePort(port);
      if (port < 3000 || port > 9999) throw new Error("exe.dev previews support ports 3000-9999");
      await running(id);
      let key = accessKeys.get(id);
      if (
        !key ||
        (key.expiresAt !== undefined && key.expiresAt - Date.now() <= SANDBOX_PREVIEW_RENEWAL_MS)
      ) {
        key = await mintPreviewKey(id);
        accessKeys.set(id, key);
      }
      return {
        url: `https://${id}.exe.xyz:${port}/`,
        headers: { "X-Exedev-Authorization": `Bearer ${key.token}` },
        ...(key.expiresAt === undefined ? {} : { expiresAt: key.expiresAt }),
      };
    },
  };
}
