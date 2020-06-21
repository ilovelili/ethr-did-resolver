import HttpProvider from "ethjs-provider-http";
import Eth from "ethjs-query";
import abi from "ethjs-abi";
import BigNumber from "bn.js";
import EthContract from "ethjs-contract";
import DidRegistryContract from "../contract/ethr-did-registry.json";
import { Buffer } from "buffer";
// https://github.com/uport-project/ethr-did-registry registry contract address
const REGISTRY = "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b";

function bytes32toString(bytes32) {
	return Buffer.from(bytes32.slice(2), "hex").toString("utf8").replace(/\0+$/, "");
}

function stringToBytes32(str) {
	const buffstr = "0x" + Buffer.from(str).slice(0, 32).toString("hex");
	return buffstr + "0".repeat(66 - buffstr.length);
}

// https://developer.uport.me/ethr-did/docs/guides/index
// The two types currently supported by DID-JWT are:
// veriKey Which adds a Secp256k1VerificationKey2018 (Default for signing general purpose JWTs)
// sigAuth Which adds a Secp256k1SignatureAuthentication2018 signer who is able to interactively authenticate as the DID's owner (log in)

const delegateTypes = {
	Secp256k1SignatureAuthentication2018: stringToBytes32("sigAuth"),
	Secp256k1VerificationKey2018: stringToBytes32("veriKey"),
};

const attrTypes = {
	sigAuth: "SignatureAuthentication2018",
	veriKey: "VerificationKey2018",
	enc: "KeyAgreementKey2019",
};

/**
  https://github.com/uport-project/ethr-did-registry/blob/develop/contracts/EthereumDIDRegistry.sol
  event DIDDelegateChanged(
    address indexed identity,
    bytes32 delegateType,
    address delegate,
    uint validTo,
    uint previousChange
  );

    event DIDAttributeChanged(
    address indexed identity,
    bytes32 name,
    bytes value,
    uint validTo,
    uint previousChange
  );  

  did document example:
  {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:example:123456789abcdefghi",
    "authentication": [{      
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }],
    "service": [{      
      "id":"did:example:123456789abcdefghi#vcs",
      "type": "VerifiableCredentialService",
      "serviceEndpoint": "https://example.com/vc/"
    }]
  }
 */
function wrapDidDocument(did, owner, history) {
	const now = new BigNumber(Math.floor(new Date().getTime() / 1000));
	// const expired = {}
	const publicKey = [
		{
			id: `${did}#owner`,
			type: "Secp256k1VerificationKey2018",
			owner: did,
			ethereumAddress: owner,
		},
	];

	const authentication = [
		{
			type: "Secp256k1SignatureAuthentication2018",
			publicKey: `${did}#owner`,
		},
	];

	let delegateCount = 0;
	const auth = {};
	const pks = {};
	const services = {};
	for (const event of history) {
		const validTo = event.validTo;
		const key = `${event._eventName}-${event.delegateType || event.name}-${event.delegate || event.value}`;
		if (validTo && validTo.gte(now)) {
			if (event._eventName === "DIDDelegateChanged") {
				delegateCount++;
				const delegateType = bytes32toString(event.delegateType);
				switch (delegateType) {
					case "sigAuth":
						auth[key] = {
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#delegate-${delegateCount}`,
						};
					// eslint-disable-line no-fallthrough
					case "veriKey":
						pks[key] = {
							id: `${did}#delegate-${delegateCount}`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: event.delegate,
						};
						break;
				}
			} else if (event._eventName === "DIDAttributeChanged") {
				const name = bytes32toString(event.name);
				const match = name.match(/^did\/(pub|auth|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
				if (match) {
					const section = match[1];
					const algo = match[2];
					const type = attrTypes[match[4]] || match[4];
					const encoding = match[6];
					switch (section) {
						// public key
						case "pub":
							delegateCount++;
							const pk = {
								id: `${did}#delegate-${delegateCount}`,
								type: `${algo}${type}`,
								owner: did,
							};
							switch (encoding) {
								case null:
								case undefined:
								case "hex":
									pk.publicKeyHex = event.value.slice(2);
									break;
								case "base64":
									pk.publicKeyBase64 = Buffer.from(event.value.slice(2), "hex").toString("base64");
									break;
								case "base58":
									pk.publicKeyBase58 = Buffer.from(event.value.slice(2), "hex").toString("base58");
									break;
								case "pem":
									pk.publicKeyPem = Buffer.from(event.value.slice(2), "hex").toString();
									break;
								default:
									pk.value = event.value;
							}
							pks[key] = pk;
							break;
						// service
						case "svc":
							services[key] = {
								type: algo,
								serviceEndpoint: Buffer.from(event.value.slice(2), "hex").toString(),
							};
							break;
					}
				}
			}
		} else {
			if (
				delegateCount > 0 &&
				(event._eventName === "DIDDelegateChanged" ||
					(event._eventName === "DIDAttributeChanged" && bytes32toString(event.name).match(/^did\/pub\//))) &&
				validTo.lt(now)
			) {
				delegateCount--;
			}
			delete auth[key];
			delete pks[key];
			delete services[key];
		}
	}

	const doc = {
		"@context": "https://w3id.org/did/v1",
		id: did,
		publicKey: publicKey.concat(Object.values(pks)),
		authentication: authentication.concat(Object.values(auth)),
	};

	if (Object.values(services).length > 0) {
		doc.service = Object.values(services);
	}

	return doc;
}

function configureProvider(conf = {}) {
	if (conf.provider) return conf.provider;
	if (conf.web3) return conf.web3.currentProvider;
	if (conf.rpcUrl) return new HttpProvider(conf.rpcUrl);
}

function configureNetwork(conf = {}) {
	const provider = configureProvider(conf);
	if (!provider) return null;

	const eth = new Eth(provider);
	const registryAddress = conf.registry || REGISTRY;
	const DidReg = new EthContract(eth)(DidRegistryContract);

	// 'at' and 'new' which can be used to create the contract instane.
	// The at method is used to create a Contract instance for a contract that has already been deployed to the Ethereum blockchain (testnet, livenet, local or otherwise).
	// The new method is used to deploy the contract to the current chain.
	// deploy first if we use localhost
	// if (conf.rpcUrl.indexOf("localhost") > -1) {
	// 	console.log("deploy smart contract");
	// 	DidReg.new((error, result) => {
	// 		if (error) throw error;
	// 	});
	// }

	const didReg = DidReg.at(registryAddress);
	return { eth, registryAddress, didReg };
}

function configureNetworks(networksConf = []) {
	const networks = {};
	for (let i = 0; i < networksConf.length; i++) {
		const net = networksConf[i];
		networks[net.name] = configureNetwork(net);
		if (networks[net.name] === null) {
			console.warn(`invalid configuration for ${net.name}`);
		}
	}
	return networks;
}

function validateNetworksAgainstConfig(networks = {}, conf = {}) {
	if (conf.provider || conf.web3 || conf.rpcUrl) {
		if (networks["mainnet"] === null) {
			throw new Error("Ethereum provider configuration for mainnet was attempted but no valid configuration was provided.");
		}
	}

	if (conf && conf.networks) {
		for (const expectedNet of conf.networks) {
			if (!networks[expectedNet.name]) {
				throw new Error(`Ethereum provider configuration for ${expectedNet.name} was attempted but no valid configuration was provided`);
			}
		}
	}

	let count = 0;
	for (const net of Object.keys(networks)) {
		if (networks[net] !== null) {
			count++;
		}
	}

	if (count === 0) {
		throw new Error("EthrDIDResolver requires a provider configuration for at least one network");
	}
}

function getResolver(conf = {}) {
	const logDecoder = abi.logDecoder(DidRegistryContract, false);

	const networks = {
		mainnet: configureNetwork(conf),
		...configureNetworks(conf.networks),
	};

	validateNetworksAgainstConfig(networks, conf);

	const lastChanged = async (identity, networkId) => {
		// https://github.com/uport-project/ethr-did-registry/blob/develop/contracts/EthereumDIDRegistry.sol
		// mapping(address => uint) public changed;
		const result = await networks[networkId].didReg.changed(identity);
		if (result) {
			return result["0"];
		}
	};

	async function changeLog(identity, networkId) {
		const history = [];
		let owner = identity;
		let previousChange = await lastChanged(identity, networkId);

		if (previousChange) {
			const ownerRecord = await networks[networkId].didReg.identityOwner(identity);
			owner = ownerRecord["0"];
		}

		while (previousChange) {
			const blockNumber = previousChange;
			const logs = await networks[networkId].eth.getLogs({
				address: networks[networkId].registryAddress,
				topics: [null, `0x000000000000000000000000${identity.slice(2)}`],
				fromBlock: previousChange,
				toBlock: previousChange,
			});

			const events = logDecoder(logs);
			previousChange = undefined;

			for (const event of events) {
				history.unshift(event);
				if (event.previousChange.lt(blockNumber)) {
					previousChange = event.previousChange;
				}
			}
		}

		return { owner, history };
	}

	async function resolve(did, parsed) {
		const fullId = parsed.id.match(/^(.*)?(0x[0-9a-fA-F]{40})$/);
		if (!fullId) throw new Error(`Not a valid ethr DID: ${did}`);
		const id = fullId[2];
		const networkId = !fullId[1] ? "mainnet" : fullId[1].slice(0, -1);

		if (!networks[networkId]) throw new Error(`No conf for networkId: ${networkId}`);

		const { owner, history } = await changeLog(id, networkId);
		return wrapDidDocument(did, owner, history);
	}

	return { ethr: resolve };
}

module.exports = {
	REGISTRY,
	bytes32toString,
	stringToBytes32,
	delegateTypes,
	attrTypes,
	wrapDidDocument,
	getResolver,
};
