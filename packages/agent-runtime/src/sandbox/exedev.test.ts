import { afterEach, expect, spyOn, test } from "bun:test";
import { createExeDevSandboxTransport } from "./exedev";

const id = "gitterm-sbx-0123456789-01234567";
const transport = createExeDevSandboxTransport({ apiKey: "test-token" });
const ndjson = (...frames: object[]) =>
  new Response(frames.map((frame) => JSON.stringify(frame)).join("\n") + "\n");

function mockExec(handle: (command: string, headers: Headers) => Response) {
  const fetchMock: typeof fetch = Object.assign(
    async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(url).toBe("https://exe.dev/exec");
      expect(init?.method).toBe("POST");
      const command = String(init?.body);
      const headers = new Headers(init?.headers);
      if (command === `ls ${id} --json`) {
        return Response.json({ vms: [{ vm_name: id, status: "running" }] });
      }
      return handle(command, headers);
    },
    { preconnect: fetch.preconnect },
  );
  return spyOn(globalThis, "fetch").mockImplementation(fetchMock);
}

afterEach(() => {
  // Restore only the fetch spy; other test files can use their own module mocks.
  fetchSpy?.mockRestore();
  fetchSpy = undefined;
});
let fetchSpy: ReturnType<typeof mockExec> | undefined;

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
