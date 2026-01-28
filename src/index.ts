import jwt, { type JwtHeader, type JwtPayload } from "jsonwebtoken";
import jwksClient, { type JwksClient } from "jwks-rsa";

/**
 * Mapa de roles por clientId retornado pelo Keycloak.
 */
export interface KeycloakResourceAccess {
	[clientId: string]: { roles: string[] };
}

/**
 * Payload JWT esperado do Keycloak, com `resource_access` opcional.
 */
export interface KeycloakJwtPayload extends JwtPayload {
	resource_access?: KeycloakResourceAccess;
}

/**
 * Opções de configuração para instanciar o validador JWT.
 */
export interface JwtValidatorOptions {
	jwksUri: string; // URL do JWKS do Keycloak
	issuer: string; // Issuer esperado (realm)
	audience?: string; // opcional: audience padrão
}

export type ErrorKey =
	| "TOKEN_NOT_PROVIDED"
	| "TOKEN_INVALID"
	| "TOKEN_NOT_YET_VALID"
	| "AUDIENCE_INVALID"
	| "ROLE_INSUFFICIENT"
	| "ROLE_MAPPING_NOT_FOUND"
	| "INTERNAL_ERROR";

export interface ErrorCatalogEntry {
	httpStatus: number;
	title: string;
	detail?: string;
	type?: string;
	externalCode?: string;
}

/**
 * Catálogo estruturado de erros para mapear respostas padronizadas.
 */
export type ErrorCatalog = Record<ErrorKey, ErrorCatalogEntry>;

/**
 * Catálogo padrão de erros retornados pelas validações.
 */
export const defaultErrorCatalog: ErrorCatalog = {
	TOKEN_NOT_PROVIDED: {
		httpStatus: 401,
		title: "Token não fornecido",
		detail: "O cabeçalho Authorization não foi enviado.",
		externalCode: "SEC-401-001",
	},
	TOKEN_INVALID: {
		httpStatus: 403,
		title: "Token inválido",
		detail: "O token não pôde ser validado.",
		externalCode: "SEC-403-001",
	},
	TOKEN_NOT_YET_VALID: {
		httpStatus: 403,
		title: "Token ainda não é válido",
		detail: "O token possui 'iat' maior que o horário atual.",
		externalCode: "SEC-403-002",
	},
	AUDIENCE_INVALID: {
		httpStatus: 403,
		title: "Audience inválida",
		detail: "O audience do token não corresponde ao esperado.",
		externalCode: "SEC-403-003",
	},
	ROLE_INSUFFICIENT: {
		httpStatus: 403,
		title: "Permissão insuficiente",
		detail: "A role exigida não foi encontrada no token.",
		externalCode: "SEC-403-004",
	},
	ROLE_MAPPING_NOT_FOUND: {
		httpStatus: 403,
		title: "Role não mapeada",
		detail: "Não há mapeamento externo configurado para essa role.",
		externalCode: "SEC-403-005",
	},
	INTERNAL_ERROR: {
		httpStatus: 500,
		title: "Erro interno",
		detail: "Falha inesperada ao validar o token.",
		externalCode: "SEC-500-001",
	},
};

export default class JwtValidator {
	private client: JwksClient;
	private issuer: string;

	/**
	 * Cria uma instância do validador buscando a configuração OpenID para descobrir o `jwks_uri` correto.
	 * Use este factory em vez do construtor direto, pois o construtor é privado.
	 * @param options Configuração básica (jwksUri do realm, issuer esperado, roleErrorMap opcional)
	 * @returns Instância pronta para validar tokens
	 * @throws Error quando a configuração OpenID não pode ser obtida ou não contém `jwks_uri`
	 */
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
	}

	/**
	 * Extrai o token bruto do header Authorization (formato "Bearer <token>").
	 * @param token Valor do header Authorization
	 * @returns token sem o prefixo ou null quando ausente/inválido
	 */
	private extractToken(token: string): string | null {
		if (!token.startsWith("Bearer ")) {
			return null;
		}

		return token.replace("Bearer ", "").trim();
	}

	/**
	 * Verifica a assinatura e o issuer do JWT usando JWKS remoto.
	 * @param token Token JWT (string) já extraído
	 * @returns Payload decodificado tipado como KeycloakJwtPayload
	 * @throws Erro com `code=TOKEN_INVALID` quando assinatura ou payload são inválidos
	 */
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
					resolve(decoded as KeycloakJwtPayload);
				},
			);
		});
	}

	/**
	 * Valida audience do token e retorna objeto de sucesso/erro pronto para consumo em APIs.
	 * @param token Header Authorization recebido (Bearer ...)
	 * @param expectedAudience Audience esperada
	 * @returns Objeto com success e detalhes do erro quando aplicável
	 */
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

	/**
	 * Valida se o token possui a role exigida para um clientId específico.
	 * @param token Header Authorization recebido (Bearer ...)
	 * @param clientId ClientId do recurso no Keycloak
	 * @param requiredRole Role obrigatória
	 * @returns Objeto com success e detalhes do erro quando aplicável
	 */
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
