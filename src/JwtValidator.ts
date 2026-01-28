// src/JwtValidator.ts

import type { NextFunction, Request, Response } from "express";
import jwt, { type JwtHeader, type JwtPayload } from "jsonwebtoken";
import jwksClient, { type JwksClient, type SigningKey } from "jwks-rsa";
import { defaultErrorCatalog } from "./ProblemDetails";
import type {
	JwtValidatorOptions,
	KeycloakJwtPayload,
	RoleErrorMap,
} from "./type";

export class JwtValidator {
	private client: JwksClient;
	private issuer: string;
	private roleErrorMap: RoleErrorMap;

	static async create(options: JwtValidatorOptions): Promise<JwtValidator> {
		const configUrl = new URL(options.jwksUri);
		if (!configUrl.pathname.endsWith("/")) {
			configUrl.pathname += "/";
		}

		const openIdUrl = `${configUrl.toString()}.well-known/openid-configuration`;
		const res = await fetch(openIdUrl);
		if (!res.ok) {
			throw new Error(
				`Failed to fetch OpenID configuration: ${res.status} ${res.statusText}`,
			);
		}

		const data = (await res.json()) as { jwks_uri?: string };
		if (!data?.jwks_uri) {
			throw new Error("jwks_uri not found in OpenID configuration");
		}

		return new JwtValidator({
			...options,
			issuer: options.jwksUri,
			jwksUri: data.jwks_uri,
		});
	}

	private constructor(options: JwtValidatorOptions) {
		this.client = jwksClient({
			jwksUri: options.jwksUri,
		});
		this.issuer = options.issuer;
		this.roleErrorMap = options.roleErrorMap ?? {};
	}

	// Exposto para facilitar testes
	private extractToken(token: string): string | null {
		if (!token.startsWith("Bearer ")) {
			return null;
		}

		return token.replace("Bearer ", "").trim();
	}

	private verifyToken(token: string): Promise<KeycloakJwtPayload> {
		return new Promise((resolve, reject) => {
			jwt.verify(
				token,
				(header: JwtHeader, cb) => {
					if (!header.kid) return cb(new Error("TOKEN_INVALID"));
					this.client.getSigningKey(header.kid as string, (err, key) => {
						if (err) return cb(err);
						if (!key) return cb(new Error("TOKEN_INVALID"));
						cb(null, key.getPublicKey());
					});
				},
				{ issuer: this.issuer, algorithms: ["RS256"] },
				(err, decoded) => {
					if (err || !decoded) {
						const e: any = err || new Error("TOKEN_INVALID");
						e.code = "TOKEN_INVALID";
						return reject(e);
					}
					resolve(decoded as JwtPayload);
				},
			);
		});
	}

	async validateAudience(token: string, expectedAudience: string) {
		const realToken = this.extractToken(token);
		if (!realToken) {
			return {
				success: false,
				error: {
					...defaultErrorCatalog.TOKEN_NOT_PROVIDED,
				},
			};
		}

		try {
			const decoded = await this.verifyToken(token);

			const aud = Array.isArray(decoded.aud) ? decoded.aud[0] : decoded.aud;

			if (!aud || aud !== expectedAudience) {
				return {
					success: false,
					error: {
						...defaultErrorCatalog.AUDIENCE_INVALID,
					},
				};
			}

			return {
				success: true,
				message: "Token is valid",
			};
		} catch (error: unknown) {
			const err = error as any;

			if (err.code === "TOKEN_INVALID") {
				return {
					success: false,
					error: {
						...defaultErrorCatalog.TOKEN_INVALID,
					},
				};
			}

			return {
				success: false,
				error: {
					...defaultErrorCatalog.INTERNAL_ERROR,
				},
			};
		}
	}

	async validateRole(token: string, clientId: string, requiredRole: string) {
		const realToken = this.extractToken(token);
		if (!realToken) {
			return {
				success: false,
				error: {
					...defaultErrorCatalog.TOKEN_NOT_PROVIDED,
				},
			};
		}

		try {
			const decoded = await this.verifyToken(token);

			const resourceAccess = decoded.resource_access || {};
			const client = resourceAccess[clientId] || {};
			const roles: string[] = client.roles || [];

			if (!roles.includes(requiredRole)) {
				return {
					success: false,
					error: {
						...defaultErrorCatalog.ROLE_INSUFFICIENT,
					},
				};
			}

			return {
				success: true,
				message: "Role is valid",
			};
		} catch (error) {
			const err = error as any;

			if (err.code === "TOKEN_INVALID") {
				return {
					success: false,
					error: {
						...defaultErrorCatalog.TOKEN_INVALID,
					},
				};
			}

			return {
				success: false,
				error: {
					...defaultErrorCatalog.INTERNAL_ERROR,
				},
			};
		}
	}
}
