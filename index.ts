import { discoverPrinters } from "./discovery";

(async () => {
    const printers = await discoverPrinters();
  
    console.log("Found printers:");
    console.log(printers);

    // [ { ip: '192.168.68.113', mac: '0:dd:f9:e:b8:1' } ]
  })();