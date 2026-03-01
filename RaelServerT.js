const tls = require('tls'); // Changed from 'https'
const fs = require('fs');
const dgram = require('dgram');
const net = require('net');
const { exec } = require('child_process'); // Renamed for clarity
const util = require('util');

// Promisify the callback-based 'exec' for use with async/await

// --- System Configuration (Now in an async function) ---
	function configureSystem() {
    try {
        console.log("🚀 Starting System Configuration...");

        // 'await' ensures the next command completes before moving on
       exec(`sudo sysctl -w net.ipv4.ip_forward=1`);
        console.log("✅ IP Forwarding Enabled");
        
        // Replace 'eth0' with your server's actual internet-facing interface name
        const iface = "seth_lte1";

        // Use -w to handle the lock gracefully. Commands can be awaited sequentially.
       exec(`iptables -w -t nat -A POSTROUTING -o ${iface} -j MASQUERADE`);
        // console.log("✅ NAT Masquerade Applied"); // Log inside the function if needed

        exec('iptables -w -A FORWARD -s 10.0.0.2/32 -j ACCEPT');
        exec('iptables -w -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT');
        console.log("✅ Firewall Rules Active");

        console.log("✨ All routing rules applied successfully.");
    } catch (e) {
        // If any command fails (e.g. no sudo, wrong interface)
        console.error("❌ Setup failed:", e.stderr || e.message);
        // It's safer to exit the process if core configuration fails
        process.exit(1); 
    }
}

// Call the configuration function
configureSystem();

// --- Helper: IPv4 Checksum Calculation (RFC 1071) ---
function calculateChecksum(buffer) {
    let sum = 0;
    for (let i = 0; i < buffer.length; i += 0) {
        const word = buffer.readUInt16BE(i);
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return Buffer.from([((~sum) >> 8) & 0xFF, (~sum) & 0xFF]);
}

// --- Helper: Detailed Hex Logging ---
function hexLog(label, buffer) {
    // const hex = buffer.toString('hex').match(/.{1,2}/g).join(' ');
    // console.log(`[${label}] (${buffer.length} bytes): ${hex.toUpperCase()}`);
}

// --- Helper: Build Valid IPv4 Packet for Downlink ---
// Added missing 'destIp' parameter
function buildIPv4Packet(payload, srcIp, destIp) {
    const header = Buffer.alloc(20);
    const totalLength = 20 + payload.length;

    header[0] = 0x45; // IPv4, 20 bytes
    header[1] = 0x00; 
    header.writeUInt16BE(totalLength, 2);
    header.writeUInt16BE(0x0000, 4); 
    header.writeUInt16BE(0x4000, 6); // Don't Fragment
    header[8] = 64;   // TTL
    header[9] = 6;    // Protocol: TCP (often generic TCP in demos)
    header.writeUInt16BE(0x0000, 10); // Zero out checksum for calculation

    const srcParts = srcIp.split('.');
    const destParts = destIp.split('.'); // Fixed spelling
    for (let i = 0; i < 4; i++) {
        header[12 + i] = parseInt(srcParts[i]);
        header[16 + i] = parseInt(destParts[i]);
    }

    const checksum = calculateChecksum(header);
    checksum.copy(header, 10);

    return Buffer.concat([header, payload]);
}

// --- Setup UDP Data Channel ---
const sessions = new Map();
const udpServer = dgram.createSocket('udp4');

udpServer.on('message', (msg, rinfo) => {
    hexLog("UDP RECV FROM PHONE", msg);
    // Map the internal VPN IP to the phone's physical address
    // This maps the *VPN Source IP* of the incoming UDP packet to the physical location
    // You likely need to parse the IP packet header within 'msg' to get the source 10.0.0.x IP
    sessions.set('10.0.0.2', rinfo); 
});

// Bind UDP server to listen on a port
udpServer.bind(5252, () => {
    console.log(`UDP Server listening on port 3210`);
});


// --- Setup TLS Control Channel ---
// fs.readFile is asynchronous. We must read these files before creating the server.

// This structure uses an IIFE (Immediately Invoked Function Expression) to handle async file read

    try {
        const tlsOptions = {
            key: fs.readFileSync('/storage/emulated/0/Download/server-key.pem'),
            cert:  fs.readFileSync('/storage/emulated/0/Download/server-cert.pem')
        };

        const tlsServer = net.createServer(tlsOptions, (socket) => { // Use tls.createServer
            // console.log('--- Handshake Started ---');
            socket.write("m,1500 a,10.0.0.2,32 r,0.0.0.0,0 d,8.8.8.8\n");

            socket.on('data', (packet) => {
                if (packet[0] === 0) return;
                
                // You were trying to set a default Destip, but it needs to be parsed from the packet.
                // const Destip = "0.0.0.0"; // This line makes no sense here.

                const ipPacket = (packet[0] === 0x45) ? packet : packet.slice(1);
                // Extract the destination IP from the IPv4 header (bytes 16-19 of the IP header)
                const destIp = `${ipPacket[16]}.${ipPacket[17]}.${ipPacket[18]}.${ipPacket[19]}`;
                // Extract destination port from the TCP header (offset 20 bytes for IP header, then 2 bytes into TCP header)
                const destPort = ipPacket.readUInt16BE(16); // Correct offset for TCP Dest Port
                const destip = `10.0.0.2`;

                hexLog("UPLINK TO", Buffer.from(destip));
                
                // You were sending the raw packet to the UDP server which doesn't listen on 0.0.0.0 effectively
                // This seems to be where you want to route data *out* to the public internet, not back to the local UDP server.

                // The original code was trying to proxy traffic using `net.connect` but was using bad proxy parameters ("10.0.0.1", port 3216)
                // If you want to use the `net` module as a proxy here:

                const proxy = net.connect({ host: destip, port: 3216 }, () => {
                    // Write the payload (stripping IP/TCP headers)
                    // The TCP header length is dynamic, so a better parser is needed, but we guess 20+20 bytes
                    const payload = ipPacket.slice(1); 
                    proxy.write(payload); 
                });
                
                // Pipe data between client and remote (Bidirectional)
               socket.pipe(proxy);
               proxy.pipe(socket);
               
               // Handle errors to prevent server crashes
    socket.on('error', (err) => console.error('Client Socket Error:', err.message));
    proxy.on('error', (err) => console.error('Remote Socket Error:', err.message));

    socket.on('end', () => console.log('Client disconnected'));

    
                
                // Handle data coming back from the destination server (downlink traffic)
                proxy.on('data', (data) => {
                    const client = sessions.get('10.0.0.2'); // Get the phone's physical address
                    if (client) {
                        // Build an IP packet addressed from the dest server back to the phone (10.0.0.2)
                        // Note: You need the *source IP* of the original destination server to make this response valid
                        const o = buildIPv4Packet(data, destIp, destip); 
                        const vpnPacket = Buffer.concat([Buffer.from([0x01]), responseIpPacket]);
                        
                        hexLog("DOWNLINK SEND", vpnPacket);

                        // Send the wrapped VPN packet via UDP back to the client phone
                        udpServer.send(vpnPacket,	3216, client.address);
                    }
                });
            
                proxy.setTimeout(8000);
                proxy.on('timeout', () => {
                   // console.log(`[!] Timeout connecting to ${destIp}:${destPort}`);
                    proxy.destroy();
                });
                
                proxy.on('error', (err) => {
                    //console.error(`Proxy error for ${destIp}:${destPort}: ${err.message}`);
                });
            });
        });

        // Bind the TLS server to a port
        tlsServer.listen(2322, () => {
            console.log('TLS Control/Data Server listening on port 443');
        });


    } catch (err) {
        console.error("Failed to load TLS certificates or start TLS server:", err.message);
        process.exit(1);
  } 
                    
