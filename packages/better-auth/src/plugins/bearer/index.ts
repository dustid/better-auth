import { serializeSignedCookie } from "better-call";
import type { BetterAuthPlugin } from "../../types/plugins";
import { parseSetCookieHeader } from "../../cookies";
import { createAuthMiddleware } from "../../api";
import { createHMAC } from "@better-auth/utils/hmac";
import type { GenericEndpointContext } from "../../types";
import type { oidcProvider } from "../oidc-provider";
import { jwtVerify } from "jose";
import { getJwksAdapter } from "../jwt/adapter";

interface BearerOptions {
	/**
	 * If true, only signed tokens
	 * will be converted to session
	 * cookies
	 *
	 * @default false
	 */
	requireSignature?: boolean;
}

const getOidcPlugin = (ctx: GenericEndpointContext) => {
	return ctx.context.options.plugins?.find(
		(plugin) => plugin.id === "oidc",
	) as ReturnType<typeof oidcProvider>;
};

const getJwks = async (ctx: GenericEndpointContext) => {
	const adapter = getJwksAdapter(ctx.context.adapter);
	const keySets = await adapter.getAllKeys();
	return {
		keys: keySets.map((keySet) => ({
			...JSON.parse(keySet.publicKey),
			kid: keySet.id,
		})),
	};
};

export async function validateToken(
	token: string,
	jwks: {
		kid: string;
		kty: string;
		use: string;
		n: string;
		e: string;
		x5c: string[];
	}[],
) {
	const header = JSON.parse(atob(token.split(".")[0]));
	const key = jwks.find((key) => key.kid === header.kid);
	if (!key) {
		throw new Error("Key not found");
	}
	const verified = await jwtVerify(token, key);
	return verified;
}

/**
 * Converts bearer token to session cookie
 */
export const bearer = (options?: BearerOptions) => {
	return {
		id: "bearer",
		hooks: {
			before: [
				{
					matcher(context) {
						return Boolean(
							context.request?.headers.get("authorization") ||
								context.headers?.get("authorization"),
						);
					},
					handler: createAuthMiddleware(async (c) => {
						const token =
							c.request?.headers.get("authorization")?.replace("Bearer ", "") ||
							c.headers?.get("Authorization")?.replace("Bearer ", "");
						if (!token) {
							return;
						}

						const oidcPlugin = getOidcPlugin(c);

						let signedToken = "";
						if (token.includes(".")) {
							// jwt
							if (oidcPlugin && oidcPlugin.options.accessTokenAsJWT) {
								// If oidc plugin present, enabled, and oidc is set to using
								// JWTs as access tokens,
								// verify its signature
								// decode if valid
								// grab the token from the payload
								// use that session token to set the cookie
								//
								// - may need to consider whether bearer plugin requireSignature is set to True
								// - ideally should only have the session id in the payload but not easily queryable
								// with internalAdapter at the moment
								try {
									const keys = await getJwks(c);
									const verified = await validateToken(token, keys.keys);
									if (!verified || !verified.payload?.tok) {
										return;
									}
									signedToken = (
										await serializeSignedCookie(
											"",
											verified.payload.tok as string,
											c.context.secret,
										)
									).replace("=", "");
								} catch (e) {
									return;
								}
							} else {
								signedToken = token.replace("=", "");
							}
						} else {
							if (options?.requireSignature) {
								return;
							}
							signedToken = (
								await serializeSignedCookie("", token, c.context.secret)
							).replace("=", "");
						}
						try {
							const decodedToken = decodeURIComponent(signedToken);
							const isValid = await createHMAC(
								"SHA-256",
								"base64urlnopad",
							).verify(
								c.context.secret,
								decodedToken.split(".")[0],
								decodedToken.split(".")[1],
							);
							if (!isValid) {
								return;
							}
						} catch (e) {
							return;
						}
						console.log("Bearer token found:", signedToken);
						const existingHeaders = (c.request?.headers ||
							c.headers) as Headers;
						const headers = new Headers({
							...Object.fromEntries(existingHeaders?.entries()),
						});
						headers.append(
							"cookie",
							`${c.context.authCookies.sessionToken.name}=${signedToken}`,
						);
						return {
							context: {
								headers,
							},
						};
					}),
				},
			],
			after: [
				{
					matcher(context) {
						return true;
					},
					handler: createAuthMiddleware(async (ctx) => {
						const setCookie = ctx.context.responseHeaders?.get("set-cookie");
						if (!setCookie) {
							return;
						}
						const parsedCookies = parseSetCookieHeader(setCookie);
						const cookieName = ctx.context.authCookies.sessionToken.name;
						const sessionCookie = parsedCookies.get(cookieName);
						if (
							!sessionCookie ||
							!sessionCookie.value ||
							sessionCookie["max-age"] === 0
						) {
							return;
						}
						const token = sessionCookie.value;
						const exposedHeaders =
							ctx.context.responseHeaders?.get(
								"access-control-expose-headers",
							) || "";
						const headersSet = new Set(
							exposedHeaders
								.split(",")
								.map((header) => header.trim())
								.filter(Boolean),
						);
						headersSet.add("set-auth-token");
						ctx.setHeader("set-auth-token", token);
						ctx.setHeader(
							"Access-Control-Expose-Headers",
							Array.from(headersSet).join(", "),
						);
					}),
				},
			],
		},
	} satisfies BetterAuthPlugin;
};
