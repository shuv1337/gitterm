import { afterEach, expect, spyOn, test } from "bun:test";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as realDelay } from "node:timers/promises";
import { createExeDevSandboxTransport } from "./exedev";

const id = "gitterm-sbx-0123456789-01234567";
const transport = createExeDevSandboxTransport({ apiKey: "test-token" });
const ndjson = (...frames: object[]) =>
  new Response(frames.map((frame) => JSON.stringify(frame)).join("\n") + "\n");

function mockExec(
  handle: (command: string, headers: Headers, signal?: AbortSignal) => Response | Promise<Response>,
  status?: () => Response | undefined,
) {
  const fetchMock: typeof fetch = Object.assign(
    async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(url).toBe("https://exe.dev/exec");
      expect(init?.method).toBe("POST");
      const command = String(init?.body);
      const headers = new Headers(init?.headers);
      if (command === `ls ${id} --json`) {
        return status?.() ?? Response.json({ vms: [{ vm_name: id, status: "running" }] });
      }
      return handle(command, headers, init?.signal ?? undefined);
    },
    { preconnect: fetch.preconnect },
  );
  return spyOn(globalThis, "fetch").mockImplementation(fetchMock);
}

afterEach(() => {
  // Restore only the fetch spy; other test files can use their own module mocks.
  fetchSpy?.mockRestore();
  fetchSpy = undefined;
  randomSpy?.mockRestore();
  randomSpy = undefined;
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  tmp = undefined;
});
let fetchSpy: ReturnType<typeof mockExec> | undefined;
let randomSpy: ReturnType<typeof spyOn<typeof Math, "random">> | undefined;
let tmp: string | undefined;

test("exec survives both the lobby lexer and the VM shell, with the remote exit and streams", async () => {
  fetchSpy = mockExec((command, headers) => {
    expect(headers.get("accept")).toBe("application/x-ndjson");
    expect(command.startsWith(`ssh ${id} `)).toBe(true);
    expect(command).toContain("timeout -k 3 25 ");
    // Use Bash for the lobby's quote removal and a second Bash for the VM shell.
    // The lobby must see just one argument after the VM name.
    const remote = Bun.spawnSync([
      "bash",
      "-c",
      `ssh() { [ "$#" = 2 ] || return 99; bash -c "$2"; }\n${command}`,
    ]);
    const stdout = Buffer.from(remote.stdout);
    return ndjson(
      { stdout: stdout.subarray(0, 1).toString("base64") },
      { stderr: Buffer.from(remote.stderr).toString("base64") },
      { stdout: stdout.subarray(1).toString("base64") },
      { exit_code: remote.exitCode },
    );
  });
  const value = `é dollars $HOME, double " and single '\nnext line`;
  const command = `printf '%s\\n' "$PAYLOAD"\nprintf '%s' 'error $literal' >&2\nexit 7`;
  expect(await transport.run(id, command, { env: { PAYLOAD: value } })).toEqual({
    exitCode: 7,
    stdout: `${value}\n`,
    stderr: "error $literal",
  });
});

test("a provider-side execution failure is not a command exit", async () => {
  fetchSpy = mockExec(() => ndjson({ error: "VM did not report an exit status" }));
  await expect(transport.run(id, "true")).rejects.toMatchObject({
    code: "provider",
    message: expect.stringContaining("VM did not report an exit status"),
  });
});

test("output without an exit frame is not a successful command", async () => {
  fetchSpy = mockExec(() => ndjson({ stdout: "aGk=" }));
  await expect(transport.run(id, "true")).rejects.toMatchObject({
    code: "provider",
    message: "exe.dev did not report the command's exit code.",
  });
});

test("preview authentication errors name the exact permission exe.dev requires", async () => {
  fetchSpy = mockExec((command) => {
    expect(command).toStartWith(`ssh-key generate-api-key --vm=${id} `);
    return Response.json({ error: "command not allowed by token permissions" }, { status: 403 });
  });
  await expect(transport.preview(id, 3456)).rejects.toMatchObject({
    code: "auth",
    message: expect.stringContaining('"ssh-key generate-api-key"'),
  });
});

test("previews use non-expiring keys where supported, with unique labels across transports", async () => {
  const labels: string[] = [];
  fetchSpy = mockExec((command) => {
    expect(command).toStartWith(`ssh-key generate-api-key --vm=${id} `);
    expect(command).toContain("--exp=never");
    const label = /--label=([^\s]+)/.exec(command)?.[1];
    expect(label).toBeDefined();
    labels.push(label!);
    return Response.json({ token: `exe1.test-${labels.length}`, expires_at: null });
  });
  const first = createExeDevSandboxTransport({ apiKey: "test-token" });
  const second = createExeDevSandboxTransport({ apiKey: "test-token" });
  expect(await first.preview(id, 3456)).toEqual({
    url: `https://${id}.exe.xyz:3456/`,
    headers: { "X-Exedev-Authorization": "Bearer exe1.test-1" },
  });
  expect((await first.preview(id, 4567)).headers["X-Exedev-Authorization"]).toBe(
    "Bearer exe1.test-1",
  );
  expect((await second.preview(id, 3456)).headers["X-Exedev-Authorization"]).toBe(
    "Bearer exe1.test-2",
  );
  expect(labels).toHaveLength(2);
  expect(labels[0]).not.toBe(labels[1]);
});

const outlives = () =>
  Response.json(
    { error: "Cannot create a new key that outlives the current key. Set a shorter --exp." },
    { status: 422 },
  );

test("a preview falls back to the provider's one-hour key and renews with fifteen minutes left", async () => {
  const transport = createExeDevSandboxTransport({ apiKey: "test-token" });
  const hour = 60 * 60_000;
  const now = Date.now();
  let time = now;
  const clock = spyOn(Date, "now").mockImplementation(() => time);
  const expiries: string[] = [];
  let issued = 0;
  fetchSpy = mockExec((command) => {
    const expiry = /--exp=([^\s]+)/.exec(command)?.[1];
    expiries.push(expiry!);
    if (expiry === "never") return outlives();
    // A deliberate offset ensures renewal uses the server timestamp, not now + one hour.
    return Response.json({
      token: `exe1.test-${++issued}`,
      expires_at: new Date(time + hour - 30_000).toISOString(),
    });
  });
  try {
    const first = await transport.preview(id, 3456);
    expect(first.expiresAt).toBe(now + hour - 30_000);
    time = first.expiresAt! - 15 * 60_000 - 1;
    expect(await transport.preview(id, 3456)).toEqual(first);
    time++;
    const renewed = await transport.preview(id, 3456);
    expect(renewed.headers["X-Exedev-Authorization"]).toBe("Bearer exe1.test-2");
    expect(renewed.expiresAt).toBe(time + hour - 30_000);
    expect(expiries).toEqual(["never", "1h", "never", "1h"]);
  } finally {
    clock.mockRestore();
  }
});

test("a token that expires before even the short preview key gets an actionable error", async () => {
  const requests: string[] = [];
  fetchSpy = mockExec((command) => {
    requests.push(command);
    return outlives();
  });
  const transport = createExeDevSandboxTransport({ apiKey: "test-token" });
  await expect(transport.preview(id, 3456)).rejects.toMatchObject({
    code: "auth",
    message: expect.stringContaining("at least one hour remaining"),
  });
  expect(requests).toEqual([
    expect.stringContaining("--exp=never"),
    expect.stringContaining("--exp=1h"),
  ]);
});

test("destroy discards the cached preview key", async () => {
  let minted = 0;
  let deleted = false;
  fetchSpy = mockExec((command) => {
    if (command === `rm ${id}`) {
      deleted = true;
      return Response.json({});
    }
    return Response.json({ token: `exe1.test-${++minted}` });
  });
  const transport = createExeDevSandboxTransport({ apiKey: "test-token" });
  const first = await transport.preview(id, 3456);
  await transport.destroy(id);
  expect(deleted).toBe(true);
  // Simulate a running VM with the same id. It must not get the destroyed VM's key.
  expect((await transport.preview(id, 3456)).headers).not.toEqual(first.headers);
  expect(minted).toBe(2);
});

const partAttempt = /\bt(\d+)\.(\d+)\b/;
const upload = (clock?: Parameters<typeof createExeDevSandboxTransport>[1]) =>
  createExeDevSandboxTransport({ apiKey: "test-token" }, clock);
const returnRunningWhenReady = (command: string) =>
  command.replace(
    'if [ "$SECONDS" -ge "$end" ]; then',
    'if [ -f "$D/pid" ] && [ -f ready ]; then echo running; exit 0; fi\n        if [ "$SECONDS" -ge "$end" ]; then',
  );

function localVm(
  intercept?: (
    command: string,
    bash: (command: string) => Promise<Response>,
    signal?: AbortSignal,
  ) => Response | Promise<Response> | undefined,
  status?: () => Response | undefined,
) {
  const root = (tmp = mkdtempSync(join(tmpdir(), "gitterm-exedev-")));
  randomSpy = spyOn(Math, "random").mockReturnValue(0);
  const commands: string[] = [];
  let jobs = 0;
  const queue: Array<() => void> = [];
  async function bash(command: string) {
    if (jobs === 4) await new Promise<void>((resolve) => queue.push(resolve));
    else jobs++;
    try {
      const child = Bun.spawn(
        ["bash", "-c", `umask 022\nssh() { [ "$#" = 2 ] || return 99; bash -c "$2"; }\n${command}`],
        {
          cwd: root,
          env: {
            ...process.env,
            HOME: root,
            TMPDIR: root,
            PATH: `${join(root, "bin")}:${process.env.PATH}`,
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).arrayBuffer(),
        new Response(child.stderr).arrayBuffer(),
        child.exited,
      ]);
      return ndjson(
        { stdout: Buffer.from(stdout).toString("base64") },
        { stderr: Buffer.from(stderr).toString("base64") },
        { exit_code: exitCode },
      );
    } finally {
      const next = queue.shift();
      if (next) next();
      else jobs--;
    }
  }
  fetchSpy = mockExec((command, _headers, signal) => {
    expect(command).toStartWith(`ssh ${id} `);
    expect(Buffer.byteLength(command)).toBeLessThanOrEqual(64_000);
    commands.push(command);
    return intercept?.(command, bash, signal) ?? bash(command);
  }, status);
  return { root, commands, busy: () => jobs > 0 };
}

function fakeClock() {
  let now = Date.UTC(2026, 0, 1);
  const timers = new Set<{ at: number; fire: () => void }>();
  return {
    now: () => now,
    timer(ms: number, fire: () => void) {
      const timer = { at: now + Math.max(1, ms), fire };
      timers.add(timer);
      return () => {
        timers.delete(timer);
      };
    },
    deadline(ms: number) {
      const controller = new AbortController();
      this.timer(ms, () => controller.abort(new DOMException("Timed out", "TimeoutError")));
      return controller.signal;
    },
    async run<T>(operation: Promise<T>, busy = () => false) {
      let settled = false;
      const result = operation.finally(() => {
        settled = true;
      });
      void result.catch(() => {});
      for (;;) {
        if (settled) return await result;
        if (busy()) {
          await realDelay(1);
          continue;
        }
        await realDelay(1);
        if (settled || busy()) continue;
        now = Math.min(...Array.from(timers, ({ at }) => at));
        if (!Number.isFinite(now)) throw new Error("No timers left for an unfinished operation");
        for (const timer of timers) {
          if (timer.at > now) continue;
          timers.delete(timer);
          timer.fire();
        }
      }
    },
  };
}

test("small and empty files each use one atomic write request", async () => {
  let checked = false;
  const { root, commands } = localVm((command, bash) => {
    if (checked) return;
    checked = true;
    // Corrupt the payload without updating the expected hash, against a pre-existing file.
    return bash(command.replace("bmV3", "b2xk"));
  });
  const path = join(root, "file");
  writeFileSync(path, "original");
  const sandbox = upload();
  await expect(sandbox.writeFile(id, path, Buffer.from("new"))).rejects.toThrow("exit 9");
  expect(readFileSync(path, "utf8")).toBe("original");
  await sandbox.writeFile(id, path, Buffer.from("new"));
  expect(readFileSync(path, "utf8")).toBe("new");
  await sandbox.writeFile(id, path, Buffer.alloc(0));
  expect(readFileSync(path)).toHaveLength(0);
  expect(commands).toHaveLength(3);
  expect(readdirSync(root)).toEqual(["file"]);
});

test("parallel parts fit the body limit and atomically assemble a hostile path", async () => {
  let active = 0;
  let peak = 0;
  const { root, commands } = localVm(async (command, bash) => {
    if (!partAttempt.test(command)) return bash(command);
    expect(command).toContain("timeout -k 3 10 ");
    peak = Math.max(peak, ++active);
    try {
      return await bash(command);
    } finally {
      active--;
    }
  });
  const name = `é spaces ' " $(touch canary)`;
  const path = join(root, name);
  const data = randomBytes(500 * 1024);
  const sandbox = upload();
  await Promise.all([sandbox.writeFile(id, path, data), sandbox.writeFile(id, "second", data)]);
  expect(readFileSync(path).equals(data)).toBe(true);
  expect(readFileSync(join(root, "second")).equals(data)).toBe(true);
  expect(readdirSync(root).toSorted()).toEqual(["second", name]);
  expect(commands).toHaveLength(28);
  expect(peak).toBeGreaterThan(1);
  expect(peak).toBeLessThanOrEqual(8);
});

test("uploads shrink parts to fit a long quote-heavy path", async () => {
  const { root, commands } = localVm();
  const parent = Array.from({ length: 2 }, () => "'".repeat(110)).join("/");
  const path = join(parent, "file");
  const data = randomBytes(45 * 1024);
  await upload().writeFile(id, path, data);
  expect(commands.filter((command) => partAttempt.test(command))).toHaveLength(2);
  expect(readFileSync(join(root, path)).equals(data)).toBe(true);
  expect(readdirSync(join(root, parent))).toEqual(["file"]);
  await expect(upload().writeFile(id, "'".repeat(10_000), data)).rejects.toThrow(
    "Upload path (10000 bytes)",
  );
});

test.each(["504", "fetch throw", "missing exit", "error frame", "corrupt part", "124", "137"])(
  "a part retries after %s and preserves file bytes",
  async (failure) => {
    const { root, commands } = localVm(async (command, bash) => {
      if (!/\bt0\.0\b/.test(command)) return bash(command);
      if (failure === "504") return new Response(null, { status: 504 });
      if (failure === "fetch throw") throw new Error("connection closed");
      if (failure === "error frame") return ndjson({ error: "VM did not report an exit status" });
      if (failure === "corrupt part")
        return bash(
          command.replace(
            /[A-Za-z0-9+/]{61440}/,
            (payload) => `${payload[0] === "A" ? "B" : "A"}${payload.slice(1)}`,
          ),
        );
      if (failure === "124" || failure === "137") return ndjson({ exit_code: Number(failure) });
      // Lose the response after the remote write; replay must replace, not append.
      await bash(command);
      return ndjson({ stdout: "" });
    });
    const path = join(root, "file");
    const data = randomBytes(100 * 1024);
    await upload().writeFile(id, path, data);
    expect(readFileSync(path).equals(data)).toBe(true);
    expect(commands.filter((command) => /\bt0\.[01]\b/.test(command))).toHaveLength(2);
    expect(readdirSync(root)).toEqual(["file"]);
  },
);

test("a burst transitions to paced uploads under a sustained provider rate limit", async () => {
  const clock = fakeClock();
  let active = 0;
  let burstPeak = 0;
  let pacedPeak = 0;
  let throttled = 0;
  let first429: number | undefined;
  let resumed: number | undefined;
  let parts = 0;
  const accepted: number[] = [];
  const { root, busy } = localVm(async (command, bash) => {
    if (!partAttempt.test(command)) return bash(command);
    const now = clock.now();
    if (first429 !== undefined) {
      resumed ??= now;
      pacedPeak = Math.max(pacedPeak, ++active);
    } else burstPeak = Math.max(burstPeak, ++active);
    const limited = ++parts > 7;
    while (accepted.length && now - accepted[0]! >= 1000) accepted.shift();
    const rejected = limited && accepted.length >= 6;
    if (limited && !rejected) accepted.push(now);
    try {
      await new Promise<void>((resolve) => clock.timer(180, resolve));
      if (rejected) {
        first429 ??= clock.now();
        throttled++;
        return new Response(null, { status: 429, headers: { "retry-after": "1" } });
      }
      return await bash(command);
    } finally {
      active--;
    }
  });
  const data = randomBytes(30 * 45 * 1024);
  const path = join(root, "file");
  await clock.run(upload(clock).writeFile(id, path, data), busy);
  expect(readFileSync(path).equals(data)).toBe(true);
  expect(throttled).toBeGreaterThan(0);
  expect(resumed! - first429!).toBeGreaterThanOrEqual(1_000);
  expect(burstPeak).toBe(8);
  expect(pacedPeak).toBeGreaterThan(0);
  expect(pacedPeak).toBeLessThanOrEqual(3);
});

test("eight simultaneous 429s back off once, then prioritize a status request", async () => {
  const clock = fakeClock();
  let refusedAt: number | undefined;
  let firstBurst = 0;
  let statusChecks = 0;
  const admitted: Array<{ time: number; kind: string }> = [];
  const sandbox = upload(clock);
  let status: ReturnType<typeof sandbox.info> | undefined;
  const { root, busy } = localVm(
    (command, bash) => {
      if (!partAttempt.test(command)) return bash(command);
      if (++firstBurst <= 8) {
        refusedAt ??= clock.now();
        if (firstBurst === 8)
          clock.timer(100, () => {
            status = sandbox.info(id);
          });
        return new Response(null, { status: 429 });
      }
      admitted.push({ time: clock.now(), kind: "part" });
      return bash(command);
    },
    () => {
      if (++statusChecks > 1) admitted.push({ time: clock.now(), kind: "status" });
      return undefined;
    },
  );
  randomSpy?.mockReturnValue(0.998);
  await clock.run(sandbox.writeFile(id, join(root, "file"), randomBytes(8 * 45 * 1024)), busy);
  await status;
  expect(admitted[0]?.kind).toBe("status");
  expect(admitted[0]!.time - refusedAt!).toBe(500);
  expect(admitted.map(({ time }) => time - admitted[0]!.time)).toEqual(
    Array.from({ length: 9 }, (_, index) => index * 125),
  );
});

test("a 429 during paced uploads wakes parts waiting for concurrency", async () => {
  const clock = fakeClock();
  const attempts = [0, 0, 0, 0];
  const { root, busy } = localVm(async (command, bash) => {
    const match = partAttempt.exec(command);
    if (!match) return bash(command);
    const index = Number(match[1]);
    const attempt = ++attempts[index]!;
    if (attempt === 1) return new Response(null, { status: 429 });
    // p2 and p3 are waiting for capacity when p0's refusal pushes the next slot back.
    if (index === 0 && attempt === 2) {
      await new Promise<void>((resolve) => clock.timer(350, resolve));
      return new Response(null, { status: 429 });
    }
    if (index === 1) await new Promise<void>((resolve) => clock.timer(700, resolve));
    return bash(command);
  });
  const data = randomBytes(4 * 45 * 1024);
  const path = join(root, "file");
  await clock.run(upload(clock).writeFile(id, path, data), busy);
  expect(attempts).toEqual([3, 2, 2, 2]);
  expect(readFileSync(path).equals(data)).toBe(true);
});

test("stale burst responses still honor a capped explicit Retry-After", async () => {
  const clock = fakeClock();
  const start = clock.now();
  let calls = 0;
  const finished: number[] = [];
  fetchSpy = mockExec((command) => {
    expect(command).toBe("ls --json");
    if (++calls === 1) return new Response(null, { status: 429 });
    if (calls === 2) return new Response(null, { status: 429, headers: { "retry-after": "600" } });
    finished.push(clock.now() - start);
    return Response.json({ vms: [] });
  });
  const sandbox = upload(clock);
  await clock.run(Promise.all([sandbox.list({}), sandbox.list({})]));
  expect(finished).toEqual([60_000, 60_125]);
});

test("200 refusals do not spend part attempts or the upload retry budget", async () => {
  const clock = fakeClock();
  const times = new Map<string, number>();
  const attemptsUsed = new Set<string>();
  let refused = 0;
  const { root, busy } = localVm((command, bash) => {
    const match = partAttempt.exec(command);
    if (!match) return bash(command);
    attemptsUsed.add(match[2]!);
    const attempts = (times.get(match[1]!) ?? 0) + 1;
    times.set(match[1]!, attempts);
    if (attempts > 5) return bash(command);
    refused++;
    return new Response(null, { status: 429, headers: { "retry-after": "0" } });
  });
  const path = join(root, "file");
  const data = randomBytes(40 * 45 * 1024);
  await clock.run(upload(clock).writeFile(id, path, data), busy);
  expect(refused).toBe(200);
  expect([...attemptsUsed]).toEqual(["0"]);
  expect(readFileSync(path).equals(data)).toBe(true);
  expect(readdirSync(root)).toEqual(["file"]);
});

test("widespread 504 exhausts the shared retry budget even when retries succeed", async () => {
  const attempts: string[] = [];
  const { root } = localVm((command, bash) => {
    const match = partAttempt.exec(command);
    if (!match) return bash(command);
    attempts.push(match[2]!);
    return match[2] === "0" ? new Response(null, { status: 504 }) : bash(command);
  });
  await expect(
    upload().writeFile(id, join(root, "file"), randomBytes(900 * 1024)),
  ).rejects.toMatchObject({
    code: "timeout",
  });
  expect(attempts.filter((attempt) => attempt === "0").length).toBeGreaterThanOrEqual(9);
  expect(attempts.filter((attempt) => attempt !== "0").length).toBeLessThanOrEqual(8);
  expect(readdirSync(root)).toEqual([]);
});

test("persistent 504 stops a part after four attempts and cleans up", async () => {
  let failed = 0;
  const { root } = localVm((command, bash) => {
    if (!/\bt0\.\d+\b/.test(command)) return bash(command);
    failed++;
    return new Response(null, { status: 504 });
  });
  await expect(
    upload().writeFile(id, join(root, "file"), randomBytes(100 * 1024)),
  ).rejects.toMatchObject({
    code: "timeout",
  });
  expect(failed).toBe(4);
  expect(readdirSync(root)).toEqual([]);
});

test("an upload deadline stops persistent 429s, reports progress, and cleans up", async () => {
  const clock = fakeClock();
  let refused = 0;
  const { root, commands, busy } = localVm((command, bash) => {
    const match = partAttempt.exec(command);
    if (!match || match[1] === "0") return bash(command);
    refused++;
    return new Response(null, { status: 429 });
  });
  const path = join(root, "file");
  writeFileSync(path, "original");
  await expect(
    clock.run(upload(clock).writeFile(id, path, randomBytes(100 * 1024)), busy),
  ).rejects.toMatchObject({
    code: "timeout",
    message: expect.stringContaining("46080/102400 bytes uploaded"),
  });
  expect(refused).toBeGreaterThan(8);
  expect(commands.at(-1)).toContain("rm -rf");
  expect(readFileSync(path, "utf8")).toBe("original");
  expect(readdirSync(root)).toEqual(["file"]);
});

test("429s on status checks and rm use the shared cooldown and retry", async () => {
  const clock = fakeClock();
  let statuses = 0;
  let removes = 0;
  let resumeAt = 0;
  fetchSpy = mockExec(
    (command) => {
      expect(command).toBe(`rm ${id}`);
      if (++removes === 1) {
        resumeAt = Math.floor(clock.now() / 1_000) * 1_000 + 2_000;
        return new Response(null, {
          status: 429,
          headers: { "retry-after": new Date(resumeAt).toUTCString() },
        });
      }
      expect(clock.now()).toBeGreaterThanOrEqual(resumeAt);
      return Response.json({});
    },
    () => {
      if (++statuses === 1) return new Response(null, { status: 429 });
      return undefined;
    },
  );
  randomSpy = spyOn(Math, "random").mockReturnValue(0);
  await clock.run(upload(clock).destroy(id));
  expect(statuses).toBe(2);
  expect(removes).toBe(2);
});

test("a fatal 403 aborts outstanding parts before cleanup and does not start more", async () => {
  let aborted = 0;
  let started = 0;
  const { root, commands } = localVm((command, bash, signal) => {
    if (!partAttempt.test(command)) return bash(command);
    started++;
    if (/\bt0\.0\b/.test(command)) return new Response(null, { status: 403 });
    return new Promise((_, reject) => {
      const abort = () => {
        aborted++;
        reject(signal?.reason);
      };
      if (signal?.aborted) abort();
      else signal?.addEventListener("abort", abort, { once: true });
    });
  });
  await expect(
    upload().writeFile(id, join(root, "file"), randomBytes(900 * 1024)),
  ).rejects.toMatchObject({
    code: "auth",
  });
  expect(started).toBe(8);
  expect(aborted).toBe(7);
  expect(commands.at(-1)).toContain("rm -rf");
  expect(readdirSync(root)).toEqual([]);
});

test("tampering before assembly leaves the pre-existing target unchanged", async () => {
  const { root } = localVm((command, bash) => {
    if (command.includes("xargs -0 cat")) {
      const dir = readdirSync(root).find((name) => name.includes(".gitterm-parts-"))!;
      const path = join(root, dir, "p000001");
      const bytes = readFileSync(path);
      bytes[0] = bytes[0]! ^ 1;
      writeFileSync(path, bytes);
    }
    return bash(command);
  });
  const path = join(root, "file");
  writeFileSync(path, "original");
  await expect(upload().writeFile(id, path, randomBytes(100 * 1024))).rejects.toThrow("exit 9");
  expect(readFileSync(path, "utf8")).toBe("original");
  expect(readdirSync(root)).toEqual(["file"]);
});

test("a fast long-timeout command returns both streams and exit in its launch request", async () => {
  const { root, commands } = localVm();
  const cwd = join(root, `dir ' " é`);
  mkdirSync(cwd);
  const value = `$HOME " ' é\nline`;
  const result = await upload().run(id, `printf '%s\\n' "$PWD" "$VALUE"; echo error >&2; exit 7`, {
    cwd,
    env: { VALUE: value },
    timeoutMs: 120_000,
  });
  expect(result).toEqual({ exitCode: 7, stdout: `${cwd}\n${value}\n`, stderr: "error\n" });
  expect(commands).toHaveLength(1);
  expect(commands[0]).toContain("timeout -k 3 25 ");
  expect(readdirSync(root)).toEqual([`dir ' " é`]);
});

test("a detached command without cwd inherits the short command's cwd and umask", async () => {
  const { root } = localVm();
  const sandbox = upload();
  const command = `pwd; umask; printf data > "$1"; stat -c %a "$1"`;
  const short = await sandbox.run(id, `set -- short; ${command}`);
  const detached = await sandbox.run(id, `set -- long; ${command}`, { timeoutMs: 60_000 });
  expect(short).toEqual({ exitCode: 0, stdout: `${root}\n0022\n644\n`, stderr: "" });
  expect(detached).toEqual(short);
  expect(readFileSync(join(root, "long"), "utf8")).toBe("data");
  expect(readdirSync(root).toSorted()).toEqual(["long", "short"]);
});

test("a detached wrapper remains live after its timeout child exits, until it records exit", async () => {
  const { root } = localVm((command, bash) => {
    if (!command.includes("setsid nohup")) return bash(command);
    return bash(
      command
        .replace('wait "$pid"\n', 'wait "$pid"\n      status=$?; sleep 0.15; (exit "$status")\n')
        .replace("sleep 0.25", "sleep 0.02"),
    );
  });
  const sandbox = upload();
  for (let run = 0; run < 8; run++) {
    expect(await sandbox.run(id, "echo ok; exit 7", { timeoutMs: 60_000 })).toEqual({
      exitCode: 7,
      stdout: "ok\n",
      stderr: "",
    });
  }
  expect(readdirSync(root)).toEqual([]);
});

test("reaping signals timeout so the command's EXIT trap runs and the process group stops", async () => {
  let group = 0;
  const { root } = localVm((command, bash) => {
    if (command.includes("setsid nohup")) return bash(returnRunningWhenReady(command));
    if (command.includes("echo lost")) {
      const dir = readdirSync(root).find((name) => name.startsWith("gitterm-run-"))!;
      group = Number(readFileSync(join(root, dir, "pid"), "utf8").split(" ")[0]);
      return new Response(null, { status: 403 });
    }
    return bash(command);
  });
  try {
    await expect(
      upload().run(
        id,
        `mkdir publish.lock; trap 'sleep 0.2; rmdir publish.lock; touch trapped' EXIT; touch ready; while :; do sleep 30; done`,
        { timeoutMs: 60_000 },
      ),
    ).rejects.toMatchObject({ code: "auth" });
    expect(readdirSync(root).toSorted()).toEqual(["ready", "trapped"]);
    expect(group).toBeGreaterThan(1);
    const ps = Bun.spawnSync(["ps", "-eo", "pgid=,stat="]);
    expect(ps.exitCode).toBe(0);
    const live = ps.stdout
      .toString()
      .trim()
      .split("\n")
      .some((line) => {
        const [pgid, state] = line.trim().split(/\s+/);
        return Number(pgid) === group && !state?.startsWith("Z");
      });
    expect(live).toBe(false);
  } finally {
    if (group > 1) {
      try {
        process.kill(-group, "SIGKILL");
      } catch {
        /* Already exited. */
      }
    }
  }
});

test("upload and launch sweeps tolerate a disappearing directory and only delete old entries", async () => {
  const { root } = localVm();
  const paths = [
    "gitterm-run-0123456789abcdef",
    "gitterm-run-fedcba9876543210",
    "file.gitterm-parts-0123456789abcdef",
    "file.gitterm-parts-fedcba9876543210",
  ];
  for (const name of paths) mkdirSync(join(root, name));
  const old = new Date(Date.now() - 3_700_000);
  for (const index of [0, 2]) utimesSync(join(root, paths[index]!), old, old);
  mkdirSync(join(root, "bin"));
  mkdirSync(join(root, "vanished"));
  writeFileSync(
    join(root, "bin/find"),
    `#!/bin/sh
set -e
/usr/bin/find "$@"
rm -rf vanished
echo 'find: vanished: No such file or directory' >&2
exit 1
`,
    { mode: 0o755 },
  );
  const sandbox = upload();
  expect(await sandbox.run(id, "echo ok", { timeoutMs: 60_000 })).toEqual({
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
  });
  mkdirSync(join(root, "vanished"));
  await sandbox.writeFile(id, "file", randomBytes(100 * 1024));
  expect(paths.map((path) => existsSync(join(root, path)))).toEqual([false, true, false, true]);
  expect(existsSync(join(root, "vanished"))).toBe(false);
});

test("a lost detached command is a provider failure, not an exit status", async () => {
  let polls = 0;
  const { commands } = localVm((command, bash) => {
    if (command.includes("setsid nohup"))
      return ndjson({ stdout: "cnVubmluZwo=" }, { exit_code: 0 });
    if (command.includes("echo lost")) {
      if (++polls === 1) return new Response(null, { status: 504 });
      return ndjson({ stdout: "bG9zdAo=" }, { exit_code: 0 });
    }
    return bash(command);
  });
  await expect(upload().run(id, "true", { timeoutMs: 120_000 })).rejects.toMatchObject({
    code: "provider",
    message: expect.stringContaining("lost"),
  });
  expect(polls).toBe(2);
  expect(commands.at(-1)).toContain("rm -rf");
});

test.each([
  { code: "provider", message: "exe.dev lost the detached command." },
  { code: "auth", message: expect.stringContaining("exe.dev rejected the token") },
])("a detached poll preserves $code after the launch admission deadline", async (failure) => {
  const clock = fakeClock();
  const running = () => ndjson({ stdout: "cnVubmluZwo=" }, { exit_code: 0 });
  let polls = 0;
  const { busy } = localVm(async (command, bash) => {
    if (command.includes("setsid nohup")) return running();
    if (!command.includes("echo lost")) return bash(command);
    await new Promise<void>((resolve) => clock.timer(20_000, resolve));
    if (++polls < 7) return running();
    return failure.code === "auth"
      ? new Response(null, { status: 403 })
      : ndjson({ stdout: "bG9zdAo=" }, { exit_code: 0 });
  });
  await expect(
    clock.run(upload(clock).run(id, "true", { timeoutMs: 300_000 }), busy),
  ).rejects.toMatchObject(failure);
  expect(polls).toBe(7);
});

test("a completed poll can be replayed when its response is lost", async () => {
  let polls = 0;
  let refreshed = false;
  const { root, commands } = localVm(async (command, bash) => {
    if (command.includes("setsid nohup")) return bash(returnRunningWhenReady(command));
    if (command.includes("echo lost") && ++polls === 1) {
      const dir = join(root, readdirSync(root).find((name) => name.startsWith("gitterm-run-"))!);
      const old = new Date(Date.now() - 3_700_000);
      utimesSync(dir, old, old);
      const result = bash(
        command.replace('while [ "$(cat "$D/boot"', 'touch polled\n      while [ "$(cat "$D/boot"'),
      );
      for (let attempt = 0; attempt < 100 && !existsSync(join(root, "polled")); attempt++)
        await realDelay(10);
      refreshed = statSync(dir).mtimeMs > old.getTime() + 3_600_000;
      writeFileSync(join(root, "release"), "");
      await result;
      throw new Error("connection closed");
    }
    return bash(command);
  });
  expect(
    await upload().run(id, "touch ready; while [ ! -f release ]; do sleep 0.02; done; echo ok", {
      timeoutMs: 60_000,
    }),
  ).toEqual({
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
  });
  expect(polls).toBe(2);
  expect(refreshed).toBe(true);
  expect(commands).toHaveLength(4);
  expect(readdirSync(root).toSorted()).toEqual(["polled", "ready", "release"]);
});

test("a throttled detached launch gets its full client deadline after admission", async () => {
  const clock = fakeClock();
  const start = clock.now();
  const acceptedAt: number[] = [];
  let statuses = 0;
  let launches = 0;
  const refuse = () => new Response(null, { status: 429, headers: { "retry-after": "45" } });
  const { busy } = localVm(
    (command, bash, signal) => {
      if (command.includes("setsid nohup")) {
        if (++launches === 1) return refuse();
        acceptedAt.push(clock.now() - start);
        return ndjson({ stdout: "cnVubmluZwo=" }, { exit_code: 0 });
      }
      if (command.includes("echo lost"))
        return new Promise((resolve, reject) => {
          const cancel = clock.timer(40_000, () => {
            signal?.removeEventListener("abort", abort);
            resolve(
              ndjson(
                { stdout: Buffer.from("done\n0\n3\nb2sK\n0\n\n").toString("base64") },
                { exit_code: 0 },
              ),
            );
          });
          const abort = () => {
            cancel();
            reject(signal?.reason);
          };
          signal?.addEventListener("abort", abort, { once: true });
        });
      return bash(command);
    },
    () => (++statuses === 1 ? refuse() : undefined),
  );
  expect(await clock.run(upload(clock).run(id, "echo ok", { timeoutMs: 45_000 }), busy)).toEqual({
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
  });
  expect(launches).toBe(2);
  expect(acceptedAt[0]).toBeGreaterThanOrEqual(90_000);
});

test("creation reports the VM wait deadline and deletes the unfinished VM", async () => {
  const clock = fakeClock();
  let name: string | undefined;
  let removed = false;
  fetchSpy = mockExec((command) => {
    if (command.startsWith("new ")) {
      name = /--name=([a-z0-9-]+)/.exec(command)?.[1];
      return Response.json({});
    }
    if (command === `ls ${name} --json`)
      return new Response(null, { status: 429, headers: { "retry-after": "60" } });
    expect(command).toBe(`rm ${name}`);
    removed = true;
    return Response.json({});
  });
  await expect(
    clock.run(upload(clock).create({ timeoutMs: 60_000, labels: {} })),
  ).rejects.toMatchObject({
    code: "timeout",
    message: "Timed out waiting for the exe.dev VM.",
  });
  expect(removed).toBe(true);
});

const unreachable = (status = 422) =>
  Response.json(
    {
      code: "vm_unreachable",
      error: "failed to connect to VM: SSH new client conn failed: ssh: handshake failed: EOF\n",
    },
    { status },
  );
const createInput = { timeoutMs: 60_000, labels: {} };
const createTimeout = { code: "timeout", message: "Timed out waiting for the exe.dev VM." };
const commandFailure = { code: "provider", message: "exe.dev failed to run a command." };

function mockCreate(
  handle: (op: string, signal?: AbortSignal) => Response | Promise<Response> | undefined,
) {
  let name: string | undefined;
  const ops: string[] = [];
  fetchSpy = mockExec((command, _headers, signal) => {
    const op = command.split(" ", 1)[0]!;
    ops.push(op);
    if (op === "new") {
      name = /--name=([a-z0-9-]+)/.exec(command)?.[1];
      expect(name).toBeDefined();
    } else if (op === "ls") {
      expect(command).toBe(`ls ${name} --json`);
    } else if (op === "ssh") {
      expect(command).toBe(`ssh ${name} 'timeout -k 3 25 bash -c '"'"'true'"'"''`);
    } else {
      expect(command).toBe(`rm ${name}`);
    }
    return (
      handle(op, signal) ??
      Response.json(op === "ls" ? { vms: [{ vm_name: name, status: "running" }] } : {})
    );
  });
  return { ops, name: () => name };
}

test.each([
  [0, [0, 250, 750, 1750, 3750]],
  [1, [0, 500, 1500, 3500, 7500]],
] satisfies [number, number[]][])(
  "creation backs off while SSH is unreachable and keeps the VM once ready (random %s)",
  async (random, offsets) => {
    const clock = fakeClock();
    const start = clock.now();
    const probes: number[] = [];
    randomSpy = spyOn(Math, "random").mockReturnValue(random);
    const { ops, name } = mockCreate((op) => {
      if (op !== "ssh") return;
      probes.push(clock.now() - start);
      return probes.length <= 4 ? unreachable() : ndjson({ exit_code: 0 });
    });
    expect(await clock.run(upload(clock).create(createInput))).toMatchObject({
      id: name(),
      state: "running",
    });
    expect(probes).toEqual(offsets);
    expect(ops).toEqual(["new", "ls", "ssh", "ssh", "ssh", "ssh", "ssh", "ls"]);
  },
);

test.each([
  [
    "403",
    () => unreachable(403),
    { code: "auth", message: expect.stringContaining("while trying to run a command.") },
  ],
  ["unrelated 422", () => Response.json({ code: "other" }, { status: 422 }), commandFailure],
  ["plain text 422", () => new Response("vm_unreachable", { status: 422 }), commandFailure],
  ["numeric code 422", () => Response.json({ code: 123 }, { status: 422 }), commandFailure],
  ["503", () => unreachable(503), commandFailure],
  [
    "504",
    () => new Response(null, { status: 504 }),
    { code: "timeout", message: "exe.dev timed out while trying to run a command." },
  ],
  [
    "fetch throw",
    () => {
      throw new Error("connection closed");
    },
    commandFailure,
  ],
  [
    "NDJSON error",
    () => ndjson({ error: "x" }),
    { code: "provider", message: "exe.dev could not run the command: x" },
  ],
  [
    "missing exit",
    () => ndjson({ stdout: "aGk=" }),
    { code: "provider", message: "exe.dev did not report the command's exit code." },
  ],
  ["nonzero exit", () => ndjson({ exit_code: 1 }), { message: "VM did not run a command" }],
] as const)("creation does not retry a readiness probe after %s", async (_case, reply, failure) => {
  const clock = fakeClock();
  let probes = 0;
  randomSpy = spyOn(Math, "random").mockReturnValue(1);
  const { ops } = mockCreate((op) => {
    if (op === "ssh") return ++probes === 1 ? reply() : ndjson({ exit_code: 0 });
  });
  await expect(clock.run(upload(clock).create(createInput))).rejects.toMatchObject(failure);
  expect(ops).toEqual(["new", "ls", "ssh", "rm"]);
});

test.each([
  ["new", "create a sandbox", ["new"]],
  ["ls", "read the sandbox", ["new", "ls", "rm"]],
] as const)("creation does not retry vm_unreachable from %s", async (failed, action, expected) => {
  const clock = fakeClock();
  const { ops } = mockCreate((op) => {
    if (op === failed) return unreachable();
  });
  await expect(clock.run(upload(clock).create(createInput))).rejects.toMatchObject({
    code: "provider",
    message: `exe.dev failed to ${action}.`,
  });
  expect(ops).toEqual([...expected]);
});

test("run does not retry vm_unreachable", async () => {
  const clock = fakeClock();
  let probes = 0;
  fetchSpy = mockExec((command) => {
    expect(command).toStartWith(`ssh ${id} `);
    return ++probes === 1 ? unreachable() : ndjson({ exit_code: 0 });
  });
  await expect(clock.run(upload(clock).run(id, "true"))).rejects.toMatchObject(commandFailure);
  expect(probes).toBe(1);
});

test("creation stops probing and deletes the VM at the shared deadline", async () => {
  const clock = fakeClock();
  const start = clock.now();
  const probes: number[] = [];
  const removals: number[] = [];
  randomSpy = spyOn(Math, "random").mockReturnValue(1);
  const { ops } = mockCreate((op) => {
    if (op === "rm") removals.push(clock.now() - start);
    if (op !== "ssh") return;
    probes.push(clock.now() - start);
    if (probes.length > 200) throw new Error("SSH probes outlived the create deadline");
    return unreachable();
  });
  await expect(clock.run(upload(clock).create(createInput))).rejects.toMatchObject(createTimeout);
  expect(probes).toHaveLength(33);
  expect(probes.every((offset) => offset < 120_000)).toBe(true);
  expect(removals).toEqual([120_000]);
  expect(ops.at(-1)).toBe("rm");
});

test.each([200, 500])("create deadline aborts an in-flight probe (rm %s)", async (status) => {
  const clock = fakeClock();
  const start = clock.now();
  const probes: number[] = [];
  let polls = 0;
  let abortedAt: number | undefined;
  randomSpy = spyOn(Math, "random").mockReturnValue(1);
  const { ops, name } = mockCreate((op, signal) => {
    // Start the probes late enough for the create deadline to beat the per-request timeout.
    if (op === "ls" && ++polls <= 2)
      return new Response(null, { status: 429, headers: { "retry-after": "40" } });
    if (op === "rm") return new Response(null, { status });
    if (op !== "ssh") return;
    probes.push(clock.now() - start);
    if (probes.length === 1) return unreachable();
    if (probes.length > 2) return ndjson({ exit_code: 0 });
    return new Promise((_, reject) => {
      signal!.addEventListener(
        "abort",
        () => {
          abortedAt = clock.now() - start;
          reject(signal!.reason);
        },
        { once: true },
      );
    });
  });
  const result = clock.run(upload(clock).create(createInput));
  await expect(result).rejects.toMatchObject(createTimeout);
  await expect(result).rejects.toHaveProperty("leftoverId", status === 500 ? name() : undefined);
  expect(probes).toEqual([80_250, 80_750]);
  expect(abortedAt).toBe(120_000);
  expect(ops).toEqual(["new", "ls", "ls", "ls", "ssh", "ssh", "rm"]);
});

test("a detached poll waits out a 429 and collects the result", async () => {
  const clock = fakeClock();
  let polls = 0;
  let retryAt = 0;
  const { busy, commands } = localVm((command, bash) => {
    if (command.includes("setsid nohup"))
      return ndjson({ stdout: "cnVubmluZwo=" }, { exit_code: 0 });
    if (!command.includes("echo lost")) return bash(command);
    if (++polls === 1) {
      retryAt = clock.now() + 1_000;
      return new Response(null, { status: 429, headers: { "retry-after": "1" } });
    }
    expect(clock.now()).toBeGreaterThanOrEqual(retryAt);
    return ndjson(
      {
        stdout: Buffer.from("done\n0\n3\nb2sK\n0\n\n").toString("base64"),
      },
      { exit_code: 0 },
    );
  });
  expect(await clock.run(upload(clock).run(id, "echo ok", { timeoutMs: 60_000 }), busy)).toEqual({
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
  });
  expect(polls).toBe(2);
  expect(commands.at(-1)).toContain("rm -rf");
});

test("a detached launch retries a 429 but never replays an uncertain 5xx", async () => {
  const clock = fakeClock();
  let launches = 0;
  const { busy, commands } = localVm((command, bash) => {
    if (!command.includes("setsid nohup")) return bash(command);
    return new Response(null, { status: ++launches === 1 ? 429 : 504 });
  });
  await expect(
    clock.run(upload(clock).run(id, "true", { timeoutMs: 60_000 }), busy),
  ).rejects.toMatchObject({ code: "timeout" });
  expect(launches).toBe(2);
  expect(commands.at(-1)).toContain("rm -rf");
});

test("detached exit 124 is returned and large output keeps a marked tail", async () => {
  const { root } = localVm();
  const result = await upload().run(id, "head -c 1048576 /dev/zero; printf tail; exit 124", {
    timeoutMs: 120_000,
  });
  expect(result.exitCode).toBe(124);
  expect(result.stdout).toStartWith("[truncated to the last 1 MiB]\n");
  expect(result.stdout).toEndWith("tail");
  expect(result.stdout.split("\n")[1]).toHaveLength(1024 * 1024);
  expect(readdirSync(root)).toEqual([]);
});

test("a 30-second timeout still uses one unchanged short command request", async () => {
  const { commands } = localVm();
  expect(await upload().run(id, "true", { timeoutMs: 30_000 })).toEqual({
    exitCode: 0,
    stdout: "",
    stderr: "",
  });
  expect(commands).toEqual([`ssh ${id} 'timeout -k 3 25 bash -c '"'"'true'"'"''`]);
});

test("oversized commands are rejected by byte count before calling exec", async () => {
  const { commands } = localVm();
  await expect(upload().run(id, "é".repeat(32_000))).rejects.toThrow("exceeds 64000 bytes");
  await expect(upload().run(id, "x".repeat(50_000), { timeoutMs: 120_000 })).rejects.toThrow(
    "exceeds 64000 bytes",
  );
  expect(commands).toEqual([]);
});
