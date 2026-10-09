import { NextRequest, NextResponse } from "next/server";
import { writeFile, unlink } from "fs/promises";
import { join } from "path";
import { spawn } from "child_process";
import { tmpdir } from "os";

function getPython(): string {
  return process.env.PYTHON_PATH ??
    ["C:", "Users", "varsh", "AppData", "Local", "Programs", "Python", "Python312", "python.exe"].join("\\");
}

export async function POST(req: NextRequest) {
  const form = await req.formData();
  const file = form.get("file") as File | null;

  if (!file) return NextResponse.json({ error: "No file uploaded" }, { status: 400 });

  const ext = file.name.split(".").pop()?.toLowerCase();
  if (!["pcap", "pcapng", "cap"].includes(ext ?? ""))
    return NextResponse.json({ error: "Only .pcap / .pcapng / .cap files allowed" }, { status: 400 });

  const bytes   = await file.arrayBuffer();
  const tmpPath = join(tmpdir(), `ctims_${Date.now()}.${ext}`);
  await writeFile(tmpPath, Buffer.from(bytes));

  const scriptPath = join(process.cwd(), "scripts", "analyze_pcap.py");

  try {
    const result = await new Promise<string>((resolve, reject) => {
      const proc = spawn(getPython(), [scriptPath, tmpPath], {
        timeout: 90000,
        env: { ...process.env, PATH: process.env.PATH + ";C:\\Program Files\\Wireshark" },
      });
      let out = "", err = "";
      proc.stdout.on("data", (d) => { out += d.toString(); });
      proc.stderr.on("data", (d) => { err += d.toString(); });
      proc.on("close", (code) => {
        if (code === 0) resolve(out);
        else reject(new Error(err || `Process exited with code ${code}`));
      });
    });

    return NextResponse.json({ success: true, filename: file.name, analysis: JSON.parse(result) });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  } finally {
    await unlink(tmpPath).catch(() => {});
  }
}
