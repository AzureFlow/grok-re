import {HttpsProxyAgent} from "https-proxy-agent";
import fetch from "node-fetch";
import secp256k1 from "secp256k1";
import {CookieJar} from "tough-cookie";
import * as constants from "./constants.js";

const jar = new CookieJar();

// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// const proxyAgent = new HttpsProxyAgent("http://127.0.0.1:8888");
const proxyAgent = undefined;

const {anonUserId, privateKey} = await createNewUser();
await performChallengeForUser({
	privateKey,
	anonUserId,
});

const result = await question('How many "r"s are in strawberry. Don\'t count.');
console.log("result:", result);

/**
 * @param {string} prompt
 * @returns {Promise<string>}
 */
export async function question(prompt) {
	const resp = await fetch("https://grok.com/rest/app-chat/conversations/new", {
		method: "POST",
		compress: true,
		body: JSON.stringify({
			systemPromptName: "",
			temporary: false,
			modelName: "grok-latest",
			message: prompt,
			fileAttachments: [],
			imageAttachments: [],
			disableSearch: false,
			enableImageGeneration: true,
			returnImageBytes: false,
			returnRawGrokInXaiRequest: false,
			enableImageStreaming: true,
			imageGenerationCount: 4,
			forceConcise: false,
			toolOverrides: {
				// imageGen: false,
				// webSearch: false,
				// xSearch: false,
				// xMediaSearch: false,
				// trendsSearch: false,
				// xPostAnalyze: false,
			},
			enableSideBySide: true,
			isPreset: false,
			sendFinalMetadata: true,
			customInstructions: "",
		}),
		headers: {
			"accept": "*/*",
			"accept-language": "en-US,en;q=0.9",
			"content-type": "application/json",
			"origin": "https://grok.com",
			"priority": "u=1, i",
			"referer": "https://grok.com/",
			"sec-ch-ua": constants.USER_AGENT_CH,
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": '"Windows"',
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": constants.USER_AGENT,
			"cookie": jar.getCookieStringSync("https://grok.com"),
		},
		agent: proxyAgent,
	});
	const content = await resp.text();

	if (!resp.ok) {
		throw new Error(`Prompt failed (${resp.status}): ${content}`);
	}

	const data = content
		.trim()
		.split("\n")
		.map((x) => JSON.parse(x).result);

	let result = "";
	for (const item of data) {
		if (!item?.response?.token) {
			continue;
		}

		result += item.response.token;
	}

	return result;
}

/**
 * @returns {Promise<{privateKey: string, anonUserId: string}>}
 */
async function createNewUser() {
	let privateKey;
	do {
		privateKey = generateBytes(32);
	} while (!secp256k1.privateKeyVerify(privateKey));

	const userPublicKey = secp256k1.publicKeyCreate(privateKey);
	const privateKeyB64 = Buffer.from(privateKey).toString("base64");

	const {anonUserId} = await registerUser(userPublicKey);

	return {
		privateKey: privateKeyB64,
		anonUserId,
	};
}

/**
 * @param {string} privateKeyB64
 * @param {string} anonUserId
 * @returns {Promise<{signature: string, challenge: string, challengeExpirationDate: Date}>}
 */
async function performChallengeForUser({privateKey: privateKeyB64, anonUserId}) {
	const {challenge, challengeExpirationTime} = await requestChallengeForUser(anonUserId);

	const challengeBuf = new Uint8Array(challenge);
	const challengeHashed = new Uint8Array(await crypto.subtle.digest("SHA-256", challengeBuf));
	const privateKey = new Uint8Array(Buffer.from(privateKeyB64, "base64"));

	const {signature} = secp256k1.ecdsaSign(challengeHashed, privateKey);
	const challengeB64 = Buffer.from(challengeBuf).toString("base64");
	const signatureB64 = Buffer.from(signature).toString("base64");

	await sendChallengeResultForUser({
		anonUserId,
		challenge: challengeB64,
		signature: signatureB64,
	});

	return {
		challenge: challengeB64,
		signature: signatureB64,
		challengeExpirationDate: challengeExpirationTime ? convertTimeObject(challengeExpirationTime) : new Date(),
	};
}

/**
 * @param {Uint8Array} userPublicKey
 * @returns {Promise<{anonUserId: string}>}
 */
async function registerUser(userPublicKey) {
	const resp = await fetch("https://grok.com/", {
		method: "POST",
		compress: true,
		body: JSON.stringify([
			{
				userPublicKey: [...userPublicKey],
			},
		]),
		headers: {
			"accept": "text/x-component",
			"accept-language": "en-US,en;q=0.9",
			"content-type": "text/plain;charset=UTF-8",
			"next-action": constants.INIT_ACTION,
			"next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
			"origin": "https://grok.com",
			"priority": "u=1, i",
			"referer": "https://grok.com/",
			"sec-ch-ua": constants.USER_AGENT_CH,
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": '"Windows"',
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": constants.USER_AGENT,
			"cookie": jar.getCookieStringSync("https://grok.com"),
		},
		agent: proxyAgent,
	});
	const content = await resp.text();

	if (!resp.ok) {
		throw new Error(`Failed to register user (${resp.status}): ${content}`);
	}

	if (resp.headers.raw()["set-cookie"]) {
		for (const cookie of resp.headers.raw()["set-cookie"]) {
			jar.setCookieSync(cookie, resp.url);
		}
	}

	return extractRSCData(content);
}

/**
 * @param {string} anonUserId
 * @returns {Promise<{challenge: number[], challengeExpirationTime: {seconds: string, nanos: number}}>}
 */
async function requestChallengeForUser(anonUserId) {
	const resp = await fetch("https://grok.com/", {
		method: "POST",
		compress: true,
		body: JSON.stringify([
			{
				anonUserId: anonUserId,
			},
		]),
		headers: {
			"accept": "text/x-component",
			"accept-language": "en-US,en;q=0.9",
			"content-type": "text/plain;charset=UTF-8",
			"next-action": constants.CHALLENGE_ACTION,
			"next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
			"origin": "https://grok.com",
			"priority": "u=1, i",
			"referer": "https://grok.com/",
			"sec-ch-ua": constants.USER_AGENT_CH,
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": '"Windows"',
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": constants.USER_AGENT,
			"cookie": jar.getCookieStringSync("https://grok.com"),
		},
		agent: proxyAgent,
	});
	const content = await resp.text();

	if (!resp.ok) {
		throw new Error(`Failed to request challenge (${resp.status}): ${content}`);
	}

	if (resp.headers.raw()["set-cookie"]) {
		for (const cookie of resp.headers.raw()["set-cookie"]) {
			jar.setCookieSync(cookie, resp.url);
		}
	}

	return extractRSCData(content);
}

/**
 * @param {{anonUserId: string, challenge: string, signature: string}} data
 * @returns {Promise<void>}
 */
async function sendChallengeResultForUser({anonUserId, challenge, signature}) {
	const resp = await fetch("https://grok.com/", {
		method: "POST",
		compress: true,
		body: JSON.stringify([
			{
				anonUserId,
				challenge,
				signature,
			},
		]),
		headers: {
			"accept": "text/x-component",
			"accept-language": "en-US,en;q=0.9",
			"content-type": "text/plain;charset=UTF-8",
			"next-action": constants.CHALLENGE_RESPONSE_ACTION,
			"next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2F%22%2C%22refresh%22%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
			"origin": "https://grok.com",
			"priority": "u=1, i",
			"referer": "https://grok.com/",
			"sec-ch-ua": constants.USER_AGENT_CH,
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": '"Windows"',
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": constants.USER_AGENT,
			"cookie": jar.getCookieStringSync("https://grok.com"),
		},
		agent: proxyAgent,
	});

	if (!resp.ok) {
		const content = await resp.text();
		throw new Error(`Failed to send challenge result (${resp.status}): ${content}`);
	}

	// sets: x-anonuserid, x-challenge, x-signature
	if (resp.headers.raw()["set-cookie"]) {
		for (const cookie of resp.headers.raw()["set-cookie"]) {
			jar.setCookieSync(cookie, resp.url);
		}
	}

	// console.log("content:", content);
	// console.log(jar.serializeSync().cookies);
}

/**
 * @param {string} content
 * @param {number} index
 * @returns {object}
 */
function extractRSCData(content, index = 1) {
	// Split content by line, get line 2, split by ":" and get data part (discard index number)
	const rscData = content.split("\n")[index].split(/\d+:/)[1];
	if (!rscData) {
		throw new Error(`Failed to extract RSC data for content: ${content}`);
	}

	return JSON.parse(rscData);
}

/**
 * @param {number} length
 * @returns {Uint8Array}
 */
function generateBytes(length) {
	const buf = new Uint8Array(length);
	crypto.getRandomValues(buf);
	return buf;
}

/**
 * @param {{seconds: string | number, nanos: number}} input
 * @returns {Date}
 */
function convertTimeObject(input) {
	if (!input) {
		return new Date();
	}

	const date = new Date(0);
	if (typeof input.seconds === "string") {
		date.setUTCSeconds(Number.parseInt(input.seconds, 10));
	} else if (typeof input.seconds === "number") {
		date.setUTCSeconds(input.seconds);
	}

	return date;
}

// /**
//  * @param {Date} date
//  * @returns {{seconds: string, nanos: number}}
//  */
// function timeToObject(date) {
// 	const time = date.getTime();
// 	return {
// 		seconds: (time / 1000).toFixed(0),
// 		nanos: time % 1000 * 1000000,
// 	};
// }
