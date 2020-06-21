import { Resolver } from "did-resolver";
import { getResolver, stringToBytes32, delegateTypes } from "../ethr-did-resolver";
import Contract from "@truffle/contract";
import DidRegistryContract from "ethr-did-registry";
import Web3 from "web3";
import ganache from "ganache-cli";
import HttpProvider from "ethjs-provider-http";

const { Secp256k1SignatureAuthentication2018, Secp256k1VerificationKey2018 } = delegateTypes;

function sleep(seconds) {
	return new Promise((resolve, reject) => setTimeout(resolve, seconds * 1000));
}

describe("ethrResolver", () => {
	// use ganache-cli
	const provider = ganache.provider();
	// use localhost
	// const localhost = "http://localhost:7545";
	// const provider = new HttpProvider(localhost); // use ethjs-provider-http instead of web3 http provider
	const DidReg = Contract(DidRegistryContract);
	const web3 = new Web3();
	web3.setProvider(provider);

	const getAccounts = () =>
		new Promise((resolve, reject) => web3.eth.getAccounts((error, accounts) => (error ? reject(error) : resolve(accounts))));
	DidReg.setProvider(provider);

	// define stop mining and start mining
	const stopMining = () =>
		new Promise((resolve, reject) =>
			web3.currentProvider.send(
				{
					jsonrpc: "2.0",
					method: "miner_stop",
					id: new Date().getTime(),
				},
				(e, val) => {
					if (e) reject(e);
					return resolve(val);
				}
			)
		);

	const startMining = () => {
		return new Promise((resolve, reject) =>
			web3.currentProvider.send(
				{
					jsonrpc: "2.0",
					method: "miner_start",
					params: [1],
					id: new Date().getTime(),
				},
				(e, val) => {
					if (e) reject(e);
					return resolve(val);
				}
			)
		);
	};

	let registry, accounts, did, identity, owner, delegate1, delegate2, ethr, didResolver;

	beforeAll(async () => {
		accounts = await getAccounts();
		identity = accounts[1].toLowerCase();
		owner = accounts[2].toLowerCase();
		delegate1 = accounts[3].toLowerCase();
		delegate2 = accounts[4].toLowerCase();
		did = `did:ethr:${identity}`;

		// deploy the contract
		registry = await DidReg.new({
			from: accounts[0],
			gasPrice: 100000000000,
			gas: 4712388, // 1779962
		});

		ethr = getResolver({ provider, registry: registry.address });
		didResolver = new Resolver(ethr);
	});

	describe("unregistered", () => {
		it("resolves document", () => {
			return expect(didResolver.resolve(did)).resolves.toEqual({
				"@context": "https://w3id.org/did/v1",
				id: did,
				publicKey: [
					{
						id: `${did}#owner`,
						type: "Secp256k1VerificationKey2018",
						owner: did,
						ethereumAddress: identity,
					},
				],
				authentication: [
					{
						type: "Secp256k1SignatureAuthentication2018",
						publicKey: `${did}#owner`,
					},
				],
			});
		});
	});

	describe("owner changed", () => {
		beforeAll(async () => {
			await registry.changeOwner(identity, owner, { from: identity });
		});

		it("resolves document", () => {
			return expect(didResolver.resolve(did)).resolves.toEqual({
				"@context": "https://w3id.org/did/v1",
				id: did,
				publicKey: [
					{
						id: `${did}#owner`,
						type: "Secp256k1VerificationKey2018",
						owner: did,
						ethereumAddress: owner,
					},
				],
				authentication: [
					{
						type: "Secp256k1SignatureAuthentication2018",
						publicKey: `${did}#owner`,
					},
				],
			});
		});
	});

	describe("delegates", () => {
		describe("add signing delegate", () => {
			beforeAll(async () => {
				await registry.addDelegate(identity, Secp256k1VerificationKey2018, delegate1, 2, { from: owner });
			});

			it("resolves document", () => {
				return expect(didResolver.resolve(did)).resolves.toEqual({
					"@context": "https://w3id.org/did/v1",
					id: did,
					publicKey: [
						{
							id: `${did}#owner`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: owner,
						},
						{
							id: `${did}#delegate-1`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: delegate1,
						},
					],
					authentication: [
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#owner`,
						},
					],
				});
			});
		});

		describe("add auth delegate", () => {
			beforeAll(async () => {
				await registry.addDelegate(identity, Secp256k1SignatureAuthentication2018, delegate2, 180, { from: owner });

				it("resolves document", () => {
					return expect(didResolver.resolve(did)).resolves.toEqual({
						"@context": "https://w3id.org/did/v1",
						id: did,
						publicKey: [
							{
								id: `${did}#owner`,
								type: "Secp256k1VerificationKey2018",
								owner: did,
								ethereumAddress: owner,
							},
							{
								id: `${did}#delegate-1`,
								type: "Secp256k1VerificationKey2018",
								owner: did,
								ethereumAddress: delegate1,
							},
							{
								id: `${did}#delegate-2`,
								type: "Secp256k1VerificationKey2018",
								owner: did,
								ethereumAddress: delegate2,
							},
						],
						authentication: [
							{
								type: "Secp256k1SignatureAuthentication2018",
								publicKey: `${did}#owner`,
							},
							{
								type: "Secp256k1SignatureAuthentication2018",
								publicKey: `${did}#delegate-2`,
							},
						],
					});
				});
			});
		});

		describe("expire automatically", () => {
			beforeAll(async () => {
				await sleep(3);
			});

			it("resolves document", () => {
				return expect(didResolver.resolve(did)).resolves.toEqual({
					"@context": "https://w3id.org/did/v1",
					id: did,
					publicKey: [
						{
							id: `${did}#owner`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: owner,
						},
						{
							id: `${did}#delegate-2`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: delegate2,
						},
					],
					authentication: [
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#owner`,
						},
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#delegate-2`,
						},
					],
				});
			});
		});

		describe("revokes delegate", () => {
			beforeAll(async () => {
				await registry.revokeDelegate(identity, Secp256k1SignatureAuthentication2018, delegate2, { from: owner });
				await sleep(1);
			});

			it("resolves document", () => {
				return expect(didResolver.resolve(did)).resolves.toEqual({
					"@context": "https://w3id.org/did/v1",
					id: did,
					publicKey: [
						{
							id: `${did}#owner`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: owner,
						},
					],
					authentication: [
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#owner`,
						},
					],
				});
			});
		});

		describe("re-add auth delegate", () => {
			beforeAll(async () => {
				await sleep(3);
				// function addDelegate(address identity, bytes32 delegateType, address delegate, uint validity) public;
				await registry.addDelegate(identity, Secp256k1SignatureAuthentication2018, delegate2, 86400, { from: owner });
			});

			it("resolves document", () => {
				return expect(didResolver.resolve(did)).resolves.toEqual({
					"@context": "https://w3id.org/did/v1",
					id: did,
					publicKey: [
						{
							id: `${did}#owner`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: owner,
						},
						{
							id: `${did}#delegate-1`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: delegate2,
						},
					],
					authentication: [
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#owner`,
						},
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#delegate-1`,
						},
					],
				});
			});
		});

		describe("attributes", () => {
			/**
				 * Public Keys
						The name of the attribute should follow this format:
						did/pub/(Secp256k1|RSA|Ed25519)/(veriKey|sigAuth)/(hex|base64)						

						// wiki
						https://github.com/uport-project/ethr-did/blob/develop/docs/guides/index.md
				 */
			describe("add publicKey", () => {
				describe("Secp256k1VerificationKey2018", () => {
					beforeAll(async () => {
						// setAttribute(address identity, bytes32 name, bytes value, uint validity)
						await registry.setAttribute(
							identity,
							/**
								* const delegateTypes = {
										Secp256k1SignatureAuthentication2018: stringToBytes32("sigAuth"),
										Secp256k1VerificationKey2018: stringToBytes32("veriKey"),
									};
								 */
							stringToBytes32("did/pub/Secp256k1/veriKey"),
							"0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
							10,
							{ from: owner }
						);

						it("resolves document", () => {
							return expect(didResolver.resolve(did)).resolves.toEqual({
								"@context": "https://w3id.org/did/v1",
								id: did,
								publicKey: [
									{
										id: `${did}#owner`,
										type: "Secp256k1VerificationKey2018",
										owner: did,
										ethereumAddress: owner,
									},
									{
										id: `${did}#delegate-1`,
										type: "Secp256k1VerificationKey2018",
										owner: did,
										ethereumAddress: delegate2,
									},
									{
										id: `${did}#delegate-2`,
										type: "Secp256k1VerificationKey2018",
										owner: did,
										publicKeyHex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
									},
								],
								authentication: [
									{
										type: "Secp256k1SignatureAuthentication2018",
										publicKey: `${did}#owner`,
									},
									{
										type: "Secp256k1SignatureAuthentication2018",
										publicKey: `${did}#delegate-1`,
									},
								],
							});
						});
					});
				});

				describe("Ed25519VerificationKey2018", () => {
					beforeAll(async () => {
						await registry.setAttribute(
							identity,
							stringToBytes32("did/pub/Ed25519/veriKey/base64"),
							"0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
							10,
							{ from: owner }
						);
					});

					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
								{
									id: `${did}#delegate-2`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									publicKeyHex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
								},
								{
									id: `${did}#delegate-3`,
									type: "Ed25519VerificationKey2018",
									owner: did,
									publicKeyBase64: Buffer.from("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", "hex").toString(
										"base64"
									),
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
						});
					});
				});

				describe("RSAVerificationKey2018", () => {
					beforeAll(async () => {
						await registry.setAttribute(
							identity,
							stringToBytes32("did/pub/RSA/veriKey/pem"),
							"-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
							10,
							{ from: owner }
						);
					});

					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
								{
									id: `${did}#delegate-2`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									publicKeyHex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
								},
								{
									id: `${did}#delegate-3`,
									type: "Ed25519VerificationKey2018",
									owner: did,
									publicKeyBase64: Buffer.from("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", "hex").toString(
										"base64"
									),
								},
								{
									id: `${did}#delegate-4`,
									type: "RSAVerificationKey2018",
									owner: did,
									publicKeyPem: "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
						});
					});
				});

				describe("X25519KeyAgreementKey2019", () => {
					let identity1, did1;

					beforeAll(async () => {
						const accounts = await getAccounts();
						identity1 = accounts[5];
						did1 = `did:ethr:${identity1}`;

						await registry.setAttribute(
							identity1,
							stringToBytes32("did/pub/X25519/enc/base64"),
							`0x${Buffer.from("MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI=", "base64").toString("hex")}`,
							86400,
							{ from: identity1 }
						);
					});

					it("resolves document", () => {
						return expect(didResolver.resolve(did1)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did1,
							publicKey: [
								{
									id: `${did1}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did1,
									ethereumAddress: identity1,
								},
								{
									id: `${did1}#delegate-1`,
									type: "X25519KeyAgreementKey2019",
									owner: did1,
									publicKeyBase64: "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI=",
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did1}#owner`,
								},
							],
						});
					});
				});
			});

			describe("revoke publicKey", () => {
				describe("Secp256k1VerificationKey2018", () => {
					beforeAll(async () => {
						//  function revokeAttribute(address identity, bytes32 name, bytes value)
						await registry.revokeAttribute(
							identity,
							stringToBytes32("did/pub/Secp256k1/veriKey"),
							"0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
							{ from: owner }
						);
						sleep(1);
					});
					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
								{
									id: `${did}#delegate-3`,
									type: "Ed25519VerificationKey2018",
									owner: did,
									publicKeyBase64: Buffer.from("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", "hex").toString(
										"base64"
									),
								},
								{
									id: `${did}#delegate-4`,
									type: "RSAVerificationKey2018",
									owner: did,
									publicKeyPem: "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
							service: [
								{
									type: "HubService",
									serviceEndpoint: "https://hubs.uport.me",
								},
							],
						});
					});
				});

				describe("Ed25519VerificationKey2018", () => {
					beforeAll(async () => {
						await registry.revokeAttribute(
							identity,
							stringToBytes32("did/pub/Ed25519/veriKey/base64"),
							"0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
							{ from: owner }
						);
						sleep(1);
					});
					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
								{
									id: `${did}#delegate-4`,
									type: "RSAVerificationKey2018",
									owner: did,
									publicKeyPem: "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
							service: [
								{
									type: "HubService",
									serviceEndpoint: "https://hubs.uport.me",
								},
							],
						});
					});
				});

				describe("RSAVerificationKey2018", () => {
					beforeAll(async () => {
						await registry.revokeAttribute(
							identity,
							stringToBytes32("did/pub/RSA/veriKey/pem"),
							"-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
							{ from: owner }
						);
						sleep(1);
					});

					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
							service: [
								{
									type: "HubService",
									serviceEndpoint: "https://hubs.uport.me",
								},
							],
						});
					});
				});
			});

			/**
			 *  When a DID is combined with a service parameter, dereferencing will return the resource pointed to from the named service endpoint,
			 * 	which was discovered by resolving the DID to its DID Document and looking up the endpoint by name.
			 * 	In this way, a Relying Party may dynamically discover and interact with the current service endpoints for a given DID.
			 * 	Services can therefore be given persistent identifiers that do not change even when the underlying service endpoints change.
			 */
			describe("add service endpoints", () => {
				describe("HubService", () => {
					beforeAll(async () => {
						await registry.setAttribute(identity, stringToBytes32("did/svc/HubService"), "https://hubs.uport.me", 10, { from: owner });
					});
					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
								{
									id: `${did}#delegate-2`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									publicKeyHex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
								},
								{
									id: `${did}#delegate-3`,
									type: "Ed25519VerificationKey2018",
									owner: did,
									publicKeyBase64: Buffer.from("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", "hex").toString(
										"base64"
									),
								},
								{
									id: `${did}#delegate-4`,
									type: "RSAVerificationKey2018",
									owner: did,
									publicKeyPem: "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
							service: [
								{
									type: "HubService",
									serviceEndpoint: "https://hubs.uport.me",
								},
							],
						});
					});
				});
			});

			describe("revoke service endpoints", () => {
				describe("HubService", () => {
					beforeAll(async () => {
						await registry.revokeAttribute(identity, stringToBytes32("did/svc/HubService"), "https://hubs.uport.me", { from: owner });
						sleep(1);
					});

					it("resolves document", () => {
						return expect(didResolver.resolve(did)).resolves.toEqual({
							"@context": "https://w3id.org/did/v1",
							id: did,
							publicKey: [
								{
									id: `${did}#owner`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: owner,
								},
								{
									id: `${did}#delegate-1`,
									type: "Secp256k1VerificationKey2018",
									owner: did,
									ethereumAddress: delegate2,
								},
							],
							authentication: [
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#owner`,
								},
								{
									type: "Secp256k1SignatureAuthentication2018",
									publicKey: `${did}#delegate-1`,
								},
							],
						});
					});
				});
			});
		});

		describe("multiple events in one block", () => {
			beforeAll(async () => {
				await stopMining();
				// promise.all: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all
				await Promise.all([
					registry.setAttribute(identity, stringToBytes32("did/svc/TestService1"), "https://test.uport.me", 10, { from: owner }),
					registry.setAttribute(identity, stringToBytes32("did/svc/TestService2"), "https://test.uport.me", 10, { from: owner }),
					sleep(1).then(() => startMining()),
				]);
			});

			it("resolves document", async () => {
				expect(await didResolver.resolve(did)).toEqual({
					"@context": "https://w3id.org/did/v1",
					id: did,
					publicKey: [
						{
							id: `${did}#owner`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: owner,
						},
						{
							id: `${did}#delegate-1`,
							type: "Secp256k1VerificationKey2018",
							owner: did,
							ethereumAddress: delegate2,
						},
					],
					authentication: [
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#owner`,
						},
						{
							type: "Secp256k1SignatureAuthentication2018",
							publicKey: `${did}#delegate-1`,
						},
					],
					service: [
						{
							type: "TestService1",
							serviceEndpoint: "https://test.uport.me",
						},
						{
							type: "TestService2",
							serviceEndpoint: "https://test.uport.me",
						},
					],
				});
			});
		});

		describe("error handling", () => {
			it("rejects promise", () => {
				return expect(didResolver.resolve("did:ethr:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX")).rejects.toEqual(
					new Error("Not a valid ethr DID: did:ethr:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX")
				);
			});
		});
	});
});
