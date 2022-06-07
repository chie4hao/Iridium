const proxy = require('udp-proxy')
const http = require('http')
const url = require('url')
const dgram = require('dgram')
const MHYbuf = require("../util/MHYbuf");
const kcp = require("node-kcp-token");
const fs = require("fs");
const pcapp = require('pcap-parser');
// const SQLiteCrud = require('sqlite3-promisify');
const DelimiterStream = require('delimiter-stream');
const util = require('util');
const path = require('path');
const execFile = util.promisify(require('child_process').execFile);
const udpPacket = require('udp-packet');
const ipPacket = require('ip-packet')
const {
	WSMessage
} = require("../util/classes");
const log = new (require("../util/log"))('Sniffer', 'blueBright');
const chalk = require('chalk');
let Session = {
	//filename
	//proxy
}
const frontend = require('./frontend-server')
const MT19937_64 = require("../util/mt64");
// async function kek() {
// 	const keysDB = new SQLiteCrud('./data/keys2.db');
// 	let r = {};
// 	let rows = await keysDB.all('SELECT * FROM keys');

// 		rows.forEach(row => {
// 			r[row.first_bytes] = Buffer.from(row.key_buffer).toString('base64');
// 		})
// 		console.log(JSON.stringify(r));
// }
// kek();
const packetQueue = [];
const DIR_SERVER = 0;
const DIR_CLIENT = 1;
const GCAP_DELIM = '█▄█\n';
const GCAP_DIR = path.join('.', 'captures')
const PACKET_GetPlayerTokenRsp = MHYbuf.getPacketIDByProtoName('GetPlayerTokenRsp');
const PACKET_UnionCmdNotify = MHYbuf.getPacketIDByProtoName('UnionCmdNotify');

let packetQueueSize = 0;
let unknownPackets = 0,
	packetOrderCount = 0;
let MHYKeys = require('../data/MHYkeys.json');
const config = require('../config');
for (let key in MHYKeys) {
	MHYKeys[key] = Buffer.from(MHYKeys[key], 'base64');
}
let initialKey;
let yuankey;
var serverBound = {};
var clientBound = {};
let UIDQueryObject = {};
const { protoRawDecode } = require('./proto_raw_decoder');

async function processMHYPacket(packet) {
	let {
		crypt,
		uncrypt,
		ip,
		overrideKey
	} = packet;
	if (uncrypt) return [uncrypt];
	if (!crypt) return log.warn("Empty data received.");

	let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
	if (crypt.byteLength <= 20) {
		yuankey = undefined;
		initialKey = undefined;
		serverBound = {};
		clientBound = {};
		switch (crypt.readInt32BE(0)) {
			case 0xFF:
				log.log("Handshake", "Connected");
				frontend.queuePacket({
					source: packetSource,
					packetID: 'HND',
					protoName: 'Handshake',
					object: 'Hamdshanke pls.'
				})
				break;
			case 404:
				log.log("Handshake", "Disconnected"); //red
				break;
			default:
				frontend.queuePacket({
					source: packetSource,
					packetID: 'HND',
					protoName: 'Handshake',
					object: 'Hamdshanke estamblished.'
				})
				// log.warn("UNKNOWN HANDSHAKE", crypt.readInt32BE(0));
				break;
		}
		return;
	}

	let KCPContextMap;
	if (packetSource == DIR_SERVER) {
		KCPContextMap = serverBound;
	} else {
		KCPContextMap = clientBound;
	}

	let peerID = ip.address + '_' + ip.port + '_' + crypt.readUInt32LE(0).toString(16);
	if (!KCPContextMap[peerID]) {
		KCPContextMap[peerID] = new kcp.KCP(crypt.readUInt32LE(0), crypt.readUInt32LE(4), ip);
		// KCPContextMap[peerID].nodelay(1, 1000, 2, 0)
		log.log('KCP', 'Instance created: ' + peerID);
	}

	let kcpobj = KCPContextMap[peerID];
	kcpobj.input(crypt)
	var hrTime = process.hrtime();
	kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000);
	kcpobj.wndsize(1024, 1024);

	let packets = [];
	let recv;
	do {
		recv = kcpobj.recv();
		if (!recv) break;
		if (!initialKey) {
			initialKey = MHYKeys[recv.readUInt16BE(0) ^ 0x4567];
		}
		let keyBuffer = overrideKey || yuankey || initialKey;
		MHYbuf.xorData(recv, keyBuffer);

		let packetID = recv.readUInt16BE(2);
		if (packetID == PACKET_GetPlayerTokenRsp) {
			var proto = await MHYbuf.dataToProtobuffer(MHYbuf.removeMagic(recv), "GetPlayerTokenRsp")
			log.debug(proto.secretKeySeed.toString())
			let initgen = new MT19937_64();
			initgen.seed(BigInt(proto.secretKeySeed));
			let generator = new MT19937_64();
			generator.seed(initgen.int64());
			generator.int64();
			let key = Buffer.alloc(4096);
			for (let i = 0; i < 4096; i += 8) {
				let val = generator.int64();
				key.writeBigUInt64BE(val, i)
			}
			yuankey = key;
		}
		packets.push(recv);
	} while (recv);
	hrTime = process.hrtime();
	kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000)
	return packets;
}

function getInfoCharacter(packetName, dir) {
	if (!isNaN(+packetName)) return ' X ';
	if (packetName.includes('Rsp')) return chalk.yellow('<--');
	if (packetName.includes('Req')) return chalk.cyan('-->');
	if (packetName.includes('Notify') && !dir) return chalk.yellowBright('<-i');
	if (packetName.includes('Notify') && dir) return chalk.cyanBright('i->');
}

function logPacket(packetSource, packetID, protoName, o, union, last) {
	// return;
	let s = '';
	if (union)
		if (last)
			s += ('      └─');
		else
			s += ('      ├─');
	s += union ? '' : new Date().toLocaleTimeString();
	s += packetSource ? chalk.cyan(' [CLIENT] ') : chalk.yellow(' [SERVER] ');
	s += `${('' + packetID).padEnd(6)}${getInfoCharacter(protoName, packetSource)}   ${('' + (protoName || '')).padEnd(20)}`;
	log.plain(s);
	log.trail(JSON.stringify(o.object) || '');

	if (last) log.log();
}

async function decodePacketProto(packet, ip) {
	let packetID = packet.readUInt16BE(2);
	let protoName = MHYbuf.getProtoNameByPacketID(packetID);
	let { ignoredProtos } = require('../config');
	if (ignoredProtos.includes(protoName)) return;

	let o = {};
	if (packetID != parseInt(protoName)) {
		let object = await MHYbuf.dataToProtobuffer(MHYbuf.parsePacketData(packet), packetID);
		o = {
			packetID,
			protoName,
			object: object,
			packet: MHYbuf.parsePacketData(packet).toString('base64')
		}
	}
	if (packetID == protoName) {
		o = {
			packetID,
			protoName,
			object: null,
			missing: true,
			packet: MHYbuf.parsePacketData(packet).toString('base64')
		}
	}
	let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
	// logPacket(packetSource, packetID, protoName, o);
	// if(o.object && o.object.scData) console.log(o.object.scData.toString('base64'))
	if (packetID == PACKET_UnionCmdNotify) {
		var commands = [];
		for (var i = 0; i < o.object.cmdList.length; i++) {
			let { messageId, body } = o.object.cmdList[i];
			let protoName = MHYbuf.getProtoNameByPacketID(messageId);
			let nested = await MHYbuf.dataToProtobuffer(body, messageId);
			commands.push({
				protoName,
				packetID: messageId,
				object: nested
			})
			// logPacket(packetSource, messageId, protoName, commands[commands.length-1], true, i == o.object.cmdList.length - 1);
		}
		o.object = {}
		o.object.cmdList = commands;
	}
	if (o) o.source = packetSource;
	// try{
	// 	o.decode = protoRawDecode(o.packet);
	// }catch(ex){

	// }
	return o;
}



function joinBuffers(buffers, delimiter = ' ') {
	let d = Buffer.from(delimiter);
	return buffers.reduce((prev, b) => Buffer.concat([prev, d, b]));
}
function delay(t) { return new Promise(resolve => setTimeout(resolve, t)) };

function queuePacket(packet) {
	packetQueue.push(packet);
	packetQueueSize++;
}


var proxyIP = '47.90.139.90';
var proxyPort = 22101;
var localaddress = "172.30.145.34";
var localport = 22105;

let count = 0;
async function execute() {
	async function loop() {
		if (!packetQueueSize) return setTimeout(loop, 32);
		let decryptedDatagram;
		let packetObject;

		while (packetQueue.length) {
			let packet = packetQueue.shift();
			packetQueueSize--;

			if (packet.ip.port !== 22101 &&
				packet.ip.port !== 22102 &&
				packet.ip.port_dst !== 22101 &&
				packet.ip.port_dst !== 22102) continue;
			// await delay(20)
			packets = await processMHYPacket(packet);
			if (!packets) continue;
			for (var i = 0; i < packets.length; i++) {
				let decryptedDatagram = packets[i];
				// log.log(packet.crypt.slice(0,40).toString('hex'));
				if (Session.datagrams) {
					let datagram;
					if (packet.ip.port === 22101 || packet.ip.port === 22102) {
						datagram = Buffer.concat([Buffer.from([0]), decryptedDatagram])
					} else {
						datagram = Buffer.concat([Buffer.from([1]), decryptedDatagram])
					}
					Session.datagrams.push(datagram);
				};
				packetObject = await decodePacketProto(decryptedDatagram, packet.ip);
				// console.log.log(JSON.stringify(packetObject));
				if (packetObject) {
					packetObject.time = packet.time;
					frontend.queuePacket(packetObject);
					dumpPacketObj(packetObject)
					count++;
				}
			}
		}
		if (Session.fileHandle && Session.datagrams && Session.datagrams.length > 0) {
			await Session.fileHandle.appendFile(Buffer.concat([joinBuffers(Session.datagrams, GCAP_DELIM), Buffer.from(GCAP_DELIM)]));
			Session.written = (Session.written || 0) + 1;
			Session.datagrams = [];
		}
		setImmediate(loop);
	}
	loop();
}

let namesToDump = config.ProtosToDump;

async function dumpPacketObj(obj) {
	// console.log(obj)
	let name = obj.protoName
	let data = obj.object


	///yeah idk why i made this async tbf 


	if (namesToDump.length == 0) return;
	// let namesToDump = []

	let count = Date.now()

	if (namesToDump.includes(name)) {
		if (!fs.existsSync("./Bins")) {
			fs.mkdirSync("./Bins")
		}

		fs.writeFileSync(`./Bins/${count}_${name}.json`, JSON.stringify(data, null, 4))
		count++;
	} else if (config.dumpAll) {
		if (!fs.existsSync("./Bins")) {
			fs.mkdirSync("./Bins")
		}

		fs.writeFileSync(`./Bins/${count}_${name}.json`, JSON.stringify(data, null, 4))
		count++;
	}

}

async function pcap(file) {
	const { Readable } = require('stream');
	const stream = Readable.from(Buffer.from(file, 'base64'));
	var parser = pcapp.parse(stream);
	parser.on('packet', packet => {
		if (packet.data.readInt16LE(12) === 8)
			packet.data = packet.data.slice(14);
		let udp = MHYbuf.read_pcap_udp_header(packet.data);
		let ip = MHYbuf.read_pcap_ipv4_header(packet.data);

		queuePacket({
			crypt: packet.data.slice(28),
			ip: {
				address: ip.src_addr,
				address_dst: ip.dst_addr,
				port: udp.port_src,
				port_dst: udp.port_dst
			},
			time: packet.header.timestampSeconds * 1000 + Math.floor(packet.header.timestampMicroseconds / 1000)
		})
	});

	parser.on('end', async () => {
		log.log('Parse finished.')
	});
}
var bsplit = require('buffer-split')
let a = 0

async function gcap(file) {

	let arr = bsplit(Buffer.from(file, "base64"), Buffer.from(GCAP_DELIM))

	//iterate through the array
	for (var i = 0; i < arr.length; i++) {
		//pass the array item to dosomething
		let datagram = arr[i]
		dosomething(datagram)
	}
	console.log(a)
}
function dosomething(packet) {
	ip = {};

	if (packet.length < 18) {
		//invalid packet
		a++
		return
	}
	if (packet.readInt8(0) == 1) {
		ip.port_dst = 22101
		ip.port = null
	} else {
		ip.port = 22101
		ip.port_dst = null
	}
	queuePacket({
		uncrypt: packet.slice(1),
		ip
	})
}

const INTERCEPT = false;

function processHandshake(msg, rinfo) {
	yuankey = undefined;
	initialKey = undefined;
	switch (msg.readInt32BE(0)) {
		case 0xFF:
			log.log("Handshake", "Connected", rinfo.address, rinfo.port);
			break;
		case 404:
			log.log("Handshake", "Disconnected", rinfo.address, rinfo.port); //red
			break;
		default:
			log.warn("UNKNOWN HANDSHAKE", msg.readInt32BE(0));
			break;
	}
}

async function processMHYPacket1(recv_tmp, ip) {
	recv = Buffer.from(recv_tmp)
	if (!initialKey) {
		console.log("initialKey:", recv.readUInt16BE(0) ^ 0x4567)
		initialKey = MHYKeys[recv.readUInt16BE(0) ^ 0x4567];
	}
	let keyBuffer = yuankey || initialKey;
	if (keyBuffer) MHYbuf.xorData(recv, keyBuffer)
	else return recv_tmp

	let packetID = recv.readUInt16BE(2);
	if (packetID == PACKET_GetPlayerTokenRsp) {
		var proto = await MHYbuf.dataToProtobuffer(MHYbuf.removeMagic(recv), "GetPlayerTokenRsp")
		log.debug(proto.secretKeySeed.toString())
		let initgen = new MT19937_64();
		initgen.seed(BigInt(proto.secretKeySeed));
		let generator = new MT19937_64();
		generator.seed(initgen.int64());
		generator.int64();
		let key = Buffer.alloc(4096);
		for (let i = 0; i < 4096; i += 8) {
			let val = generator.int64();
			key.writeBigUInt64BE(val, i)
		}
		yuankey = key;
	}
	let packetObject = await decodePacketProto(recv, ip);
	// console.log.log(JSON.stringify(packetObject));
	if (packetObject) {
		if (packetID == 4034 || packetID == 4003) {
			frontend.queuePacket(packetObject);
			// dumpPacketObj(packetObject)
		}
		count++;
		// if (packetObject.object && (packetID == 4049 || packetID == 4003)) {
		// if (packetObject.object) {

		// let data = await MHYbuf.objToProtobuffer(packetObject.object, packetID)
		// let packet = await MHYbuf.dataToPacket(data, packetID, keyBuffer)
		// return packet
		// }
		if (packetObject.object && (packetID == 4034)) {
			if (UIDQueryObject[packetObject.object.uid]) {
				UIDQueryObject[packetObject.object.uid].end(JSON.stringify(packetObject.object))
				Reflect.deleteProperty(UIDQueryObject, packetObject.object.uid)
				console.log(Object.keys(UIDQueryObject))
				return
			}
		}
	}
	return recv_tmp;
}

async function startProxySession(filename, ip, port) {
	Session = {};
	if (!filename) filename = new Date().toISOString().replace('T', '_').replace(/:/g, '-').split('.')[0] + '.gcap';
	Session.filename = path.resolve(path.join(GCAP_DIR, filename));

	Session.fileHandle = await fs.promises.open(Session.filename, 'w');
	Session.datagrams = [];

	var serverkcpobj
	var clientBound = dgram.createSocket('udp4');
	var serverBound = dgram.createSocket('udp4');
	var clients = {}
	let interval = 10
	let rinfoaddress
	let rinfoport
	let UIDQueryQueue = [];

	var output = function (data, size, context) {
		clientBound.send(data, 0, size, context.port, context.address);
	};

	clientBound.on('error', (err) => {
		console.log(`server error:\n${err.stack}`);
		clientBound.close();
	});

	clientBound.on('message', (msg, rinfo) => {
		if (msg.length <= 20) {
			processHandshake(msg, rinfo)
			clients = {};
			serverBound.send(msg, 0, msg.length, proxyPort, proxyIP);
			rinfoaddress = rinfo.address
			rinfoport = rinfo.port
			log.log("Clientmessage", rinfoaddress, rinfoport)
			return
		}
		var k = rinfo.address + '_' + rinfo.port;
		if (undefined === clients[k]) {
			var context = {
				address: rinfo.address,
				port: rinfo.port
			};
			var kcpobj = new kcp.KCP(msg.readUInt32LE(0), msg.readUInt32LE(4), context);
			kcpobj.nodelay(0, interval, 0, 0);
			kcpobj.output(output);

			serverkcpobj = new kcp.KCP(msg.readUInt32LE(0), msg.readUInt32LE(4), { address: proxyIP, port: proxyPort });
			serverkcpobj.nodelay(0, interval, 0, 0);
			serverkcpobj.output((data, size, context) => {
				serverBound.send(data, 0, size, context.port, context.address);
			});
			clients[k] = kcpobj;
		}
		var kcpobj = clients[k];
		kcpobj.input(msg);
	});

	clientBound.on('listening', () => {
		var address = clientBound.address();
		console.log(`server listening ${address.address} : ${address.port}`);
		setInterval(() => {
			for (var k in clients) {
				var kcpobj = clients[k];
				kcpobj.update(Date.now());
				// kcpobj.wndsize(1024, 1024)
				var recv = kcpobj.recv();
				if (recv) {
					processMHYPacket1(recv, kcpobj.context()).then((packet) => {
						// console.log(`clientBound recv ${recv} from ${kcpobj.context().address}:${kcpobj.context().port}`);
						if (packet) {
							serverkcpobj.send(packet)
						}
					});
				}
			}
		}, interval);
	});

	clientBound.bind(localport, localaddress);


	serverBound.on('error', (err) => {
		console.log(`client error:\n${err.stack}`);
		serverBound.close();
	});

	serverBound.on('message', (msg, rinfo) => {
		if (msg.length <= 20) {
			processHandshake(msg, rinfo)
			clients = {};
			clientBound.send(msg, 0, msg.length, rinfoport, rinfoaddress);
			log.log("Servermessage", rinfo.address, rinfo.port, rinfoport, rinfoaddress)
			return
		}
		serverkcpobj.input(msg);
	});

	setInterval(() => {
		if (!serverkcpobj) return
		serverkcpobj.update(Date.now());
		// serverkcpobj.wndsize(1024, 1024)
		var recv = serverkcpobj.recv();
		if (recv) {
			processMHYPacket1(recv, serverkcpobj.context()).then((packet) => {
				for (var k in clients) {
					var kcpobj = clients[k];
					if (packet) {
						kcpobj.send(packet)
					}
				}
			})
		}
	}, interval);

	var httpServer = http.createServer((req, res) => {
		console.log(req.url)
		let queryObject = url.parse(req.url, true).query
		if (!queryObject || !queryObject.uid) return
		if (!(queryObject.uid <= 999999999 && queryObject.uid >= 100000000)) return
		UIDQueryObject[queryObject.uid] = res

		res.setTimeout(9000, () => {
			res.writeHead(408);
			res.end()
			if (UIDQueryObject[queryObject.uid]) {
				Reflect.deleteProperty(UIDQueryObject, queryObject.uid)
			}
		})
		if (UIDQueryQueue.length <= 50) {
			UIDQueryQueue.push(queryObject.uid)
		}
	})
	httpServer.listen(3000);

	setInterval(() => {
		let uid = UIDQueryQueue.shift()
		if (uid) {
			let keyBuffer = yuankey;
			if (keyBuffer) {
				MHYbuf.objToProtobuffer({ uid: uid }, 4003).then(data => {
					return MHYbuf.dataToPacket(data, 4003, keyBuffer)
				}).then(packet => {
					serverkcpobj.send(packet)
				})
			}
		}
	}, 120);
}

async function stopProxySession() {
	if (Session.proxy) {
		Session.proxy.close();
		log.stop("UDP", 'proxy stopped')
	}
	if (Session.fileHandle) await Session.fileHandle.close();
	if (!Session.written && Session.filename) fs.unlinkSync(Session.filename);
	Session = {};
}

function getSessionStatus() {
	return !!Session.proxy;
}

async function updateProxyIP(ip, port) {
	if (Session.proxy && proxyIP !== ip || Session.proxy && proxyPort !== port) {
		log.refresh('Relaunching proxy with an updated IP and port...')
		await stopProxySession();
		startProxySession(undefined, ip, port);
	}
	proxyIP = ip;
	proxyPort = port;
	console.log
}

module.exports = {
	execute,
	pcap, gcap,
	startProxySession, stopProxySession, getSessionStatus, updateProxyIP,
	queuePacket
}
