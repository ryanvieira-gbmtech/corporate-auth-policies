import jwt from "jsonwebtoken";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JwtValidator, type KeycloakJwtPayload } from "../src";

// Mock jwks-rsa to avoid network (factory is hoisted; define inline with no outer refs)
vi.mock("jwks-rsa", () => {
	const clientMock = vi.fn(() => ({
		getSigningKey: (
			_kid: string,
			cb: (err: Error | null, key?: { getPublicKey: () => string }) => void,
		) => {
			cb(null, { getPublicKey: () => "public-key" });
		},
	}));

	return {
		__esModule: true,
		default: clientMock,
	};
});

function mockFetchWellKnown(jwksUri = "https://jwks.mock/keys") {
	const fetchMock = vi.fn().mockResolvedValue({
		ok: true,
		json: async () => ({ jwks_uri: jwksUri }),
	});
	(globalThis as any).fetch = fetchMock;
	return fetchMock;
}

function mockJwtVerifySuccess(payload: KeycloakJwtPayload) {
	vi.spyOn(jwt, "verify").mockImplementation(
		(token: string, _getKey: any, _options: any, cb: any) => {
			cb(null, payload);
		},
	);
}

function mockJwtVerifyError(message = "invalid") {
	vi.spyOn(jwt, "verify").mockImplementation(
		(_token: string, _getKey: any, _options: any, cb: any) => {
			const err: any = new Error(message);
			err.code = "TOKEN_INVALID";
			cb(err, undefined);
		},
	);
}

describe("JwtValidator public API", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		delete (globalThis as any).fetch;
		vi.clearAllMocks();
	});

	describe("create()", () => {
		it("deve instanciar usando jwks_uri retornado do openid-configuration", async () => {
			const fetchMock = mockFetchWellKnown("https://jwks.local/keys");

			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			expect(validator).toBeInstanceOf(JwtValidator);
			expect(fetchMock).toHaveBeenCalledWith(
				"https://idp.local/realm/.well-known/openid-configuration",
			);
		});

		it("deve falhar quando fetch retorna status não OK", async () => {
			(globalThis as any).fetch = vi
				.fn()
				.mockResolvedValue({ ok: false, status: 500, statusText: "err" });

			await expect(
				JwtValidator.create({
					jwksUri: "https://idp.local/realm",
					issuer: "iss",
				}),
			).rejects.toThrow(/Failed to fetch OpenID configuration/);
		});

		it("deve falhar quando openid-configuration não traz jwks_uri", async () => {
			(globalThis as any).fetch = vi
				.fn()
				.mockResolvedValue({ ok: true, json: async () => ({}) });

			await expect(
				JwtValidator.create({
					jwksUri: "https://idp.local/realm",
					issuer: "iss",
				}),
			).rejects.toThrow(/jwks_uri not found/);
		});
	});

	describe("validateAudience", () => {
		it("retorna TOKEN_NOT_PROVIDED quando header não tem Bearer", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({} as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateAudience(
				"token-sem-prefixo",
				"hub",
			);
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Token não fornecido");
		});

		it("retorna AUDIENCE_INVALID quando aud não corresponde", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({ aud: "outro" } as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateAudience("Bearer tok", "hub");
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Audience inválida");
		});

		it("retorna sucesso quando audience confere (string ou array)", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({ aud: ["hub", "outro"] } as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateAudience("Bearer tok", "hub");
			expect(result.success).toBe(true);
		});

		it("propaga TOKEN_INVALID quando verify falha", async () => {
			mockFetchWellKnown();
			mockJwtVerifyError();
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateAudience("Bearer tok", "hub");
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Token inválido");
		});
	});

	describe("validateRole", () => {
		it("retorna TOKEN_NOT_PROVIDED quando header não tem Bearer", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({} as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateRole(
				"token-sem-prefixo",
				"client",
				"admin",
			);
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Token não fornecido");
		});

		it("retorna ROLE_INSUFFICIENT quando role não encontrada", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({
				resource_access: {
					"hub-ag": { roles: ["viewer"] },
				},
			} as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateRole(
				"Bearer tok",
				"hub-ag",
				"admin",
			);
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Permissão insuficiente");
		});

		it("retorna sucesso quando role existe", async () => {
			mockFetchWellKnown();
			mockJwtVerifySuccess({
				resource_access: {
					"hub-ag": { roles: ["admin", "viewer"] },
				},
			} as KeycloakJwtPayload);
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateRole(
				"Bearer tok",
				"hub-ag",
				"admin",
			);
			expect(result.success).toBe(true);
		});

		it("propaga TOKEN_INVALID quando verify falha", async () => {
			mockFetchWellKnown();
			mockJwtVerifyError();
			const validator = await JwtValidator.create({
				jwksUri: "https://idp.local/realm",
				issuer: "https://idp.local/realm",
			});

			const result = await validator.validateRole(
				"Bearer tok",
				"hub-ag",
				"admin",
			);
			expect(result.success).toBe(false);
			expect(result.error?.title).toBe("Token inválido");
		});
	});
});
