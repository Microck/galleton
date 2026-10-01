import { readFile } from "node:fs/promises";
import { Galleton } from "../sdk/typescript/dist/index.js";

const stateDir = process.env.GALLETON_DIR ?? "./state";
const token = (await readFile(`${stateDir}/api.token`, "utf8")).trim();
const sessions = new Galleton({ token, baseURL: process.env.GALLETON_URL });
const response = await sessions.request("demo", "http://127.0.0.1:9909/me");
console.log(response.status, response.json());
