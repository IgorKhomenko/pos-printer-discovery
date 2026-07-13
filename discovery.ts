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

type Subnet = {
  network: number;
  mask: number;
  address: string;
  name: string;
};

// -----------------------------
// Subnet helpers
// -----------------------------
function ipv4ToInt(ip: string): number {
  return (
    ip
      .split(".")
      .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0
  );
}

function intToIpv4(n: number): string {
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255,
  ].join(".");
}

const VIRTUAL_INTERFACE =
  /^(lo|awdl|utun|bridge|veth|docker|tun|tap|ap|ppp|gif|stf|xhc|anpi|rvi|pktap)/i;

function isPhysicalNetworkInterface(name: string): boolean {
  if (VIRTUAL_INTERFACE.test(name)) return false;

  // if (/^(eth|em|wlan|wifi)\d/i.test(name)) return true;
  // if (/^wlp\d+s\d+/i.test(name)) return true; // Linux: wlp9s0
  // if (/^wlx/i.test(name)) return true; // Linux: USB Wi‑Fi
  // if (/^en[ops]\d/i.test(name)) return true;
  // if (/^en\d+$/i.test(name)) return true; // macOS: en0 = Wi‑Fi, en5 = USB ethernet
  // if (/^(Ethernet|Wi-Fi)(\s|\d|$)/i.test(name)) return true;
  if (/^(eth|em|en|wl|ww)/i.test(name)) return true;

  return false;
}

function isLinkLocalAddress(ip: string): boolean {
  return ip.startsWith("169.254.");
}

function getLocalSubnets(): Subnet[] {
  const seen = new Set<string>();
  const subnets: Subnet[] = [];

  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (!addrs || !isPhysicalNetworkInterface(name)) continue;

    for (const iface of addrs) {
      if (iface.internal) continue;
      if (iface.family !== "IPv4") continue;
      if (isLinkLocalAddress(iface.address)) continue;

      const mask = ipv4ToInt(iface.netmask);
      const network = (ipv4ToInt(iface.address) & mask) >>> 0;
      const key = `${network}:${mask}`;

      if (seen.has(key)) continue;
      seen.add(key);

      subnets.push({ network, mask, address: iface.address, name });
    }
  }

  return subnets;
}

function generateSubnetIps(subnet: Subnet): string[] {
  const network = subnet.network >>> 0;
  const mask = subnet.mask >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const ips: string[] = [];

  for (let ip = network + 1; ip < broadcast; ip++) {
    ips.push(intToIpv4(ip));
  }

  return ips;
}

// -----------------------------
// Get MAC address for a single IP
// -----------------------------
function getMacAddress(ip: string): Promise<string | undefined> {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    return Promise.resolve(undefined);
  }

  return new Promise((resolve) => {
    exec(`arp -n ${ip}`, (err, stdout) => {
      if (err) return resolve(undefined);

      // macOS: ? (192.168.68.113) at 00:11:22:33:44:55 on en0
      // Linux: 192.168.68.113 ether 00:11:22:33:44:55 C eth0
      const match = stdout.match(
        /\b([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b/i
      );
      resolve(match?.[1]);
    });
  });
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
  const results: R[] = new Array(array.length);
  let index = 0;

  async function worker() {
    while (index < array.length) {
      const i = index++;
      results[i] = await iteratorFn(array[i]);
    }
  }

  const workers = Array.from(
    { length: Math.min(limit, array.length) },
    () => worker()
  );
  await Promise.all(workers);

  return results;
}

function elapsedSeconds(start: number): string {
  return ((performance.now() - start) / 1000).toFixed(3);
}

// -----------------------------
// Main scan function
// -----------------------------
export async function discoverPrinters(): Promise<Device[]> {
  const totalStart = performance.now();
  console.log("Discovering printers...");

  let start = performance.now();
  const subnets = getLocalSubnets();
  console.log({subnets});
  const ips = [
    ...new Set(subnets.flatMap((subnet) => generateSubnetIps(subnet))),
  ];
  console.log(
    `[subnets] ${elapsedSeconds(start)}s (${subnets.length} subnets, ${ips.length} IPs)`
  );

  if (ips.length === 0) {
    console.log(`[total] ${elapsedSeconds(totalStart)}s`);
    return [];
  }

  start = performance.now();
  const scanResults = await asyncPool(50, ips, async (ip) => {
    const isOpen = await checkPort9100(ip);
    return isOpen ? ip : null;
  });

  const foundIps = scanResults.filter((ip): ip is string => ip !== null);
  console.log(
    `[port scan] ${elapsedSeconds(start)}s (${foundIps.length} open on port 9100)`
  );

  if (foundIps.length === 0) {
    console.log(`[total] ${elapsedSeconds(totalStart)}s`);
    return [];
  }

  start = performance.now();
  const printers = await asyncPool(10, foundIps, async (ip) => ({
    ip,
    mac: await getMacAddress(ip),
  }));
  console.log(`[mac lookup] ${elapsedSeconds(start)}s`);
  console.log(`[total] ${elapsedSeconds(totalStart)}s`);

  return printers;
}
