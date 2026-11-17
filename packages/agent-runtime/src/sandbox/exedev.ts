import { randomBytes } from "node:crypto";
import {
  accountHash,
  classifyFailure,
  discardFailedCreate,
  SANDBOX_PROVIDER_PROFILES,
  SandboxProviderError,
  shellQuote,
  terminated,
  validateLifetime,
  validatePort,
  type SandboxProviderInfo,
  type SandboxTransport,
} from "./types";

const profile = SANDBOX_PROVIDER_PROFILES.exedev;
export const DEFAULT_EXEDEV_SANDBOX_IMAGE = "node:22-bookworm";
const NAME_PREFIX = "gitterm-sbx-";
/** exe.dev's exec API accepts 64 KB request bodies; base64 chunks stay well below it. */
const WRITE_CHUNK_BYTES = 40 * 1024;
const READ_CHUNK_BYTES = 4 * 1024 * 1024;
const PREVIEW_KEY_LIFETIME_MS = 60 * 60_000;

type VmList = { vms?: Array<{ vm_name: string; status?: string }> };

/**
 * An exe.dev VM from a plain image (the default `exeuntu` image ships coding agents).
 * exe.dev has no lifetime or auto-delete, so a VM runs until destroyed. The exec API
 * allows 30 s and 64 KB per request: jobs launch detached and uploads are chunked.
 */
export function createExeDevSandboxTransport(config: {
  apiKey: string;
  image?: string;
  /** Used when no machine profile is given, as exe.dev's `new` flags take them. */
  cpu?: number;
  memory?: string;
  disk?: string;
}): SandboxTransport {
  if (!config.apiKey?.trim()) throw new SandboxProviderError("auth", "exe.dev token is empty.");
  const accessKeys = new Map<string, { token: string; expiresAt: number }>();

  async function exec(command: string, action: string, accept = "text/plain"): Promise<string> {
    let response: Response;
    try {
      response = await fetch("https://exe.dev/exec", {
        method: "POST",
        headers: { authorization: `Bearer ${config.apiKey}`, "content-type": "text/plain", accept },
        body: command,
        signal: AbortSignal.timeout(45_000),
      });
    } catch (error) {
      throw classifyFailure("exe.dev", error, action);
    }
    const text = await response.text();
    if (response.status === 401 || response.status === 403)
      throw new SandboxProviderError(
        "auth",
        `exe.dev rejected the token while trying to ${action}. Sandbox tokens need cmds new, ls, ssh, pause, resume, and rm. Private previews also need the exact subcommand "ssh-key generate-api-key".`,
      );
    if (response.status === 504)
      throw new SandboxProviderError("timeout", `exe.dev timed out while trying to ${action}.`);
    if (response.status === 422 && text.includes("Cannot create a new key that outlives"))
      throw new SandboxProviderError(
        "auth",
        "exe.dev needs a sandbox token with at least one hour remaining to create a private preview key.",
      );
    if (!response.ok)
      throw classifyFailure(
        "exe.dev",
        new Error(`${response.status} ${text.slice(0, 200)}`),
        action,
      );
    return text;
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

  async function info(id: string): Promise<SandboxProviderInfo> {
    if (!/^[a-z0-9-]+$/.test(id)) throw new Error("Invalid exe.dev VM name");
    try {
      const vm = parseList(await exec(`ls ${id} --json`, "read the sandbox")).vms?.find(
        (item) => item.vm_name === id,
      );
      return vm ? infoFrom(id, vm.status) : terminated(id);
    } catch (error) {
      if (error instanceof SandboxProviderError && error.code === "not_found")
        return terminated(id);
      throw error;
    }
  }

  async function ssh(id: string, command: string, timeoutMs = 25_000) {
    // The lobby lexes the request first, then the VM shell parses the resulting command.
    // Pass one lobby argument containing the entire VM command, with its own shell quoting.
    const remote = `timeout ${Math.max(1, Math.floor(timeoutMs / 1000))} bash -c ${shellQuote(command)}`;
    const text = await exec(
      `ssh ${id} ${shellQuote(remote)}`,
      "run a command",
      "application/x-ndjson",
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
        throw new SandboxProviderError("provider", "exe.dev returned invalid command output.");
      }
      if (typeof frame?.error === "string")
        throw new SandboxProviderError(
          "provider",
          `exe.dev could not run the command: ${frame.error}`,
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
    throw new SandboxProviderError("provider", "exe.dev did not report the command's exit code.");
  }

  async function running(id: string) {
    const current = await info(id);
    if (current.state !== "running")
      throw new SandboxProviderError("not_found", `The exe.dev VM is ${current.state}.`);
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
        const deadline = Date.now() + 120_000;
        while ((await info(name)).state !== "running") {
          if (Date.now() > deadline)
            throw new SandboxProviderError("timeout", "Timed out waiting for the exe.dev VM.");
          await new Promise((resolve) => setTimeout(resolve, 1_000));
        }
        const check = await ssh(name, "true");
        if (check.exitCode !== 0) throw new Error("VM did not run a command");
        return info(name);
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
      if ((await info(id)).state === "terminated") return;
      await exec(`rm ${id}`, "delete the sandbox");
    },

    async pause(id) {
      await exec(`pause ${id}`, "pause the sandbox");
    },

    async resume(id) {
      await exec(`resume ${id}`, "resume the sandbox");
    },

    async run(id, command, options = {}) {
      await running(id);
      const exports = Object.entries(options.env ?? {})
        .map(([key, value]) => {
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
            throw new Error(`Invalid variable name: ${key}`);
          return `export ${key}=${shellQuote(value)}; `;
        })
        .join("");
      const cd = options.cwd ? `cd ${shellQuote(options.cwd)} && ` : "";
      // The exec API allows 30 s per request; longer work belongs in jobs.
      return ssh(id, `${exports}${cd}${command}`, Math.min(options.timeoutMs ?? 25_000, 25_000));
    },

    async writeFile(id, path, data) {
      await running(id);
      const target = shellQuote(path);
      const begin = await ssh(id, `mkdir -p "$(dirname ${target})" && : > ${target}`);
      if (begin.exitCode !== 0)
        throw new SandboxProviderError("provider", "Could not create the file in the VM.");
      for (let offset = 0; offset < data.byteLength; offset += WRITE_CHUNK_BYTES) {
        const chunk = Buffer.from(data.subarray(offset, offset + WRITE_CHUNK_BYTES)).toString(
          "base64",
        );
        const appended = await ssh(id, `printf %s ${chunk} | base64 -d >> ${target}`);
        if (appended.exitCode !== 0)
          throw new SandboxProviderError("provider", "Could not upload the file to the VM.");
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
      if (!key || key.expiresAt <= Date.now()) {
        // exe.dev refuses a key that outlives its parent and rejects duplicate labels.
        // Use a fresh label so another process can also open a preview of this VM.
        const label = `gitterm-sandbox-${randomBytes(8).toString("hex")}`;
        const expiresAt = Date.now() + PREVIEW_KEY_LIFETIME_MS;
        const output = await exec(
          `ssh-key generate-api-key --vm=${id} --label=${label} --exp=1h`,
          "create a preview key",
        );
        const token = output.match(/exe[01]\.[A-Za-z0-9._-]+/)?.[0];
        if (!token)
          throw new SandboxProviderError("provider", "exe.dev did not return a VM access key.");
        key = { token, expiresAt };
        accessKeys.set(id, key);
      }
      return {
        url: `https://${id}.exe.xyz:${port}/`,
        headers: { "X-Exedev-Authorization": `Bearer ${key.token}` },
      };
    },
  };
}
