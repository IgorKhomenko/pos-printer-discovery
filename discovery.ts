import { exec } from "child_process";
import net from "net";
import os from "os";

// -----------------------------
// Types
// -----------------------------
type Device = {
  ip: string;
  mac?: string;
};

// -----------------------------
// Get ARP table
// -----------------------------
function getArpTable(): Promise<string> {
  return new Promise((resolve, reject) => {
    exec("arp -a", (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

// -----------------------------
// Parse ARP output (macOS/Linux)
// -----------------------------
function parseArp(output: string): Device[] {
  const devices: Device[] = [];

  const lines = output.split("\n");

  for (const line of lines) {
    // macOS example:
    // ? (192.168.68.120) at 00:11:22:33:44:55 on en0
    const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)/i);

    if (match) {
      devices.push({
        ip: match[1],
        mac: match[2],
      });
    }
  }

  return devices;
}

// -----------------------------
// Check if port 9100 is open
// -----------------------------
function checkPort9100(ip: string, timeout = 300): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    let done = false;

    const finish = (result: boolean) => {
      if (!done) {
        done = true;
        socket.destroy();
        resolve(result);
      }
    };

    socket.setTimeout(timeout);

    socket.connect(9100, ip, () => {
      finish(true);
    });

    socket.on("error", () => finish(false));
    socket.on("timeout", () => finish(false));
  });
}

// -----------------------------
// Limit concurrency (important)
// -----------------------------
async function asyncPool<T, R>(
  limit: number,
  array: T[],
  iteratorFn: (item: T) => Promise<R>
): Promise<R[]> {
  const ret: R[] = [];
  const executing: Promise<any>[] = [];

  for (const item of array) {
    const p = Promise.resolve().then(() => iteratorFn(item));
    ret.push(await p);

    if (limit <= array.length) {
      const e: Promise<any> = p.then(() =>
        executing.splice(executing.indexOf(e), 1)
      );
      executing.push(e);

      if (executing.length >= limit) {
        await Promise.race(executing);
      }
    }
  }

  return ret;
}

// -----------------------------
// Main scan function
// -----------------------------
export async function discoverPrinters() {
  const arpOutput = await getArpTable();
//   console.log(arpOutput);
  const devices = parseArp(arpOutput);

  const results: Device[] = [];

  await asyncPool(20, devices, async (device) => {
    const isOpen = await checkPort9100(device.ip);

    if (isOpen) {
      results.push(device);
    }
  });

  return results;
}