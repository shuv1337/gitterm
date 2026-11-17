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

test("previews use expiring VM keys with unique labels and reuse them across ports", async () => {
  const requests: string[] = [];
  fetchSpy = mockExec((command) => {
    expect(command).toMatch(
      new RegExp(
        `^ssh-key generate-api-key --vm=${id} --label=gitterm-sandbox-[a-f0-9]+ --exp=1h$`,
      ),
    );
    requests.push(command);
    return Response.json({ token: `exe1.test-${requests.length}` });
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
  expect(requests).toHaveLength(2);
  expect(requests[0]).not.toBe(requests[1]);
});

test("a token that expires before the preview key gets an actionable error", async () => {
  fetchSpy = mockExec(() =>
    Response.json(
      { error: "Cannot create a new key that outlives the current key. Set a shorter --exp." },
      { status: 422 },
    ),
  );
  await expect(transport.preview(id, 3456)).rejects.toMatchObject({
    code: "auth",
    message: expect.stringContaining("at least one hour remaining"),
  });
});
