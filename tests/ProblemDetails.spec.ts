// tests/ProblemDetails.spec.ts
import { describe, it, expect } from "vitest";
import {
  ProblemDetails,
  ErrorKey,
  ErrorCatalogEntry,
  ErrorCatalog,
  defaultErrorCatalog
} from "../src/ProblemDetails";

describe("ProblemDetails", () => {
  describe("Tipos e Interfaces", () => {
    it("deve permitir criar um ProblemDetails básico", () => {
      const problem: ProblemDetails = {
        title: "Erro de autenticação",
        status: 401
      };

      expect(problem.title).toBe("Erro de autenticação");
      expect(problem.status).toBe(401);
    });

    it("deve permitir criar um ProblemDetails completo", () => {
      const problem: ProblemDetails = {
        type: "https://errors.nstech.com.br/auth/unauthorized",
        title: "Token não fornecido",
        status: 401,
        detail: "O cabeçalho Authorization não foi enviado.",
        instance: "/api/secure",
        errorKey: "TOKEN_NOT_PROVIDED",
        errorCode: "AUTH_UNAUTHORIZED_0001",
        timestamp: "2024-01-01T12:00:00Z",
        correlationId: "abc-123-def-456"
      };

      expect(problem.title).toBe("Token não fornecido");
      expect(problem.status).toBe(401);
      expect(problem.errorKey).toBe("TOKEN_NOT_PROVIDED");
      expect(problem.errorCode).toBe("AUTH_UNAUTHORIZED_0001");
    });

    it("deve permitir propriedades extras", () => {
      const problem: ProblemDetails = {
        title: "Erro customizado",
        status: 400,
        customField: "Valor customizado",
        anotherField: 123
      };

      expect(problem.customField).toBe("Valor customizado");
      expect(problem.anotherField).toBe(123);
    });
  });

  describe("ErrorKey", () => {
    it("deve conter todas as chaves de erro definidas", () => {
      const validKeys: ErrorKey[] = [
        "TOKEN_NOT_PROVIDED",
        "TOKEN_INVALID",
        "TOKEN_NOT_YET_VALID",
        "AUDIENCE_INVALID",
        "ROLE_INSUFFICIENT",
        "ROLE_MAPPING_NOT_FOUND",
        "INTERNAL_ERROR"
      ];

      validKeys.forEach(key => {
        expect(key).toBeDefined();
      });
    });

    it("deve ser usado corretamente no ProblemDetails", () => {
      const problems: Array<{ errorKey: ErrorKey } & ProblemDetails> = [
        {
          title: "Token não fornecido",
          status: 401,
          errorKey: "TOKEN_NOT_PROVIDED"
        },
        {
          title: "Token inválido",
          status: 403,
          errorKey: "TOKEN_INVALID"
        },
        {
          title: "Permissão insuficiente",
          status: 403,
          errorKey: "ROLE_INSUFFICIENT"
        }
      ];

      expect(problems).toHaveLength(3);
      expect(problems[0].errorKey).toBe("TOKEN_NOT_PROVIDED");
      expect(problems[1].errorKey).toBe("TOKEN_INVALID");
      expect(problems[2].errorKey).toBe("ROLE_INSUFFICIENT");
    });
  });

  describe("ErrorCatalogEntry", () => {
    it("deve permitir criar uma entrada básica", () => {
      const entry: ErrorCatalogEntry = {
        httpStatus: 401,
        title: "Token não fornecido"
      };

      expect(entry.httpStatus).toBe(401);
      expect(entry.title).toBe("Token não fornecido");
    });

    it("deve permitir criar uma entrada completa", () => {
      const entry: ErrorCatalogEntry = {
        httpStatus: 403,
        title: "Permissão insuficiente",
        detail: "A role exigida não foi encontrada no token.",
        type: "https://errors.nstech.com.br/auth/forbidden",
        externalCode: "AUTH_FORBIDDEN_0002"
      };

      expect(entry.httpStatus).toBe(403);
      expect(entry.title).toBe("Permissão insuficiente");
      expect(entry.detail).toBe("A role exigida não foi encontrada no token.");
      expect(entry.externalCode).toBe("AUTH_FORBIDDEN_0002");
    });
  });

  describe("ErrorCatalog", () => {
    it("deve permitir criar um catálogo customizado", () => {
      const customCatalog: ErrorCatalog = {
        TOKEN_NOT_PROVIDED: {
          httpStatus: 401,
          title: "Credencial ausente",
          detail: "É necessário fornecer um token de acesso.",
          externalCode: "AUTH-001"
        },
        TOKEN_INVALID: {
          httpStatus: 403,
          title: "Credencial inválida",
          detail: "O token fornecido é inválido ou expirou.",
          externalCode: "AUTH-002"
        }
      };

      expect(customCatalog.TOKEN_NOT_PROVIDED.httpStatus).toBe(401);
      expect(customCatalog.TOKEN_INVALID.title).toBe("Credencial inválida");
    });
  });

  describe("defaultErrorCatalog", () => {
    it("deve conter todas as chaves de erro", () => {
      const expectedKeys: ErrorKey[] = [
        "TOKEN_NOT_PROVIDED",
        "TOKEN_INVALID",
        "TOKEN_NOT_YET_VALID",
        "AUDIENCE_INVALID",
        "ROLE_INSUFFICIENT",
        "ROLE_MAPPING_NOT_FOUND",
        "INTERNAL_ERROR"
      ];

      expectedKeys.forEach(key => {
        expect(defaultErrorCatalog[key]).toBeDefined();
        expect(defaultErrorCatalog[key].httpStatus).toBeDefined();
        expect(defaultErrorCatalog[key].title).toBeDefined();
      });
    });

    it("deve ter os status HTTP corretos", () => {
      expect(defaultErrorCatalog.TOKEN_NOT_PROVIDED.httpStatus).toBe(401);
      expect(defaultErrorCatalog.TOKEN_INVALID.httpStatus).toBe(403);
      expect(defaultErrorCatalog.TOKEN_NOT_YET_VALID.httpStatus).toBe(403);
      expect(defaultErrorCatalog.AUDIENCE_INVALID.httpStatus).toBe(403);
      expect(defaultErrorCatalog.ROLE_INSUFFICIENT.httpStatus).toBe(403);
      expect(defaultErrorCatalog.ROLE_MAPPING_NOT_FOUND.httpStatus).toBe(403);
      expect(defaultErrorCatalog.INTERNAL_ERROR.httpStatus).toBe(500);
    });

    it("deve ter títulos descritivos", () => {
      expect(defaultErrorCatalog.TOKEN_NOT_PROVIDED.title).toBe("Token não fornecido");
      expect(defaultErrorCatalog.TOKEN_INVALID.title).toBe("Token inválido");
      expect(defaultErrorCatalog.AUDIENCE_INVALID.title).toBe("Audience inválida");
      expect(defaultErrorCatalog.ROLE_INSUFFICIENT.title).toBe("Permissão insuficiente");
      expect(defaultErrorCatalog.INTERNAL_ERROR.title).toBe("Erro interno");
    });

    it("deve ter detalhes descritivos", () => {
      expect(defaultErrorCatalog.TOKEN_NOT_PROVIDED.detail).toBe("O cabeçalho Authorization não foi enviado.");
      expect(defaultErrorCatalog.TOKEN_INVALID.detail).toBe("O token não pôde ser validado.");
      expect(defaultErrorCatalog.AUDIENCE_INVALID.detail).toBe("O audience do token não corresponde ao esperado.");
      expect(defaultErrorCatalog.ROLE_INSUFFICIENT.detail).toBe("A role exigida não foi encontrada no token.");
    });

    it("deve ter códigos externos formatados corretamente", () => {
      expect(defaultErrorCatalog.TOKEN_NOT_PROVIDED.externalCode).toBe("SEC-401-001");
      expect(defaultErrorCatalog.TOKEN_INVALID.externalCode).toBe("SEC-403-001");
      expect(defaultErrorCatalog.TOKEN_NOT_YET_VALID.externalCode).toBe("SEC-403-002");
      expect(defaultErrorCatalog.AUDIENCE_INVALID.externalCode).toBe("SEC-403-003");
      expect(defaultErrorCatalog.ROLE_INSUFFICIENT.externalCode).toBe("SEC-403-004");
      expect(defaultErrorCatalog.ROLE_MAPPING_NOT_FOUND.externalCode).toBe("SEC-403-005");
      expect(defaultErrorCatalog.INTERNAL_ERROR.externalCode).toBe("SEC-500-001");
    });

    it("deve permitir conversão para ProblemDetails", () => {
      const errorKey: ErrorKey = "TOKEN_NOT_PROVIDED";
      const catalogEntry = defaultErrorCatalog[errorKey];
      
      const problem: ProblemDetails = {
        type: `https://errors.nstech.com.br/${errorKey.toLowerCase()}`,
        title: catalogEntry.title,
        status: catalogEntry.httpStatus,
        detail: catalogEntry.detail,
        errorKey: errorKey,
        errorCode: catalogEntry.externalCode
      };

      expect(problem.title).toBe("Token não fornecido");
      expect(problem.status).toBe(401);
      expect(problem.errorKey).toBe("TOKEN_NOT_PROVIDED");
      expect(problem.errorCode).toBe("SEC-401-001");
    });

    it("deve ter detalhes para todas as entradas", () => {
      Object.values(defaultErrorCatalog).forEach(entry => {
        expect(entry.detail).toBeDefined();
        expect(typeof entry.detail).toBe("string");
        expect(entry.detail!.length).toBeGreaterThan(0);
      });
    });

    it("deve ter códigos externos únicos", () => {
      const externalCodes = Object.values(defaultErrorCatalog)
        .map(entry => entry.externalCode)
        .filter(code => code !== undefined);

      const uniqueCodes = new Set(externalCodes);
      expect(uniqueCodes.size).toBe(externalCodes.length);
    });
  });

  describe("Integração com JwtValidator", () => {
    it("deve mapear erros do JwtValidator para ProblemDetails", () => {
      const errorMapping: Record<string, ErrorKey> = {
        "TOKEN_NOT_PROVIDED": "TOKEN_NOT_PROVIDED",
        "TOKEN_INVALID": "TOKEN_INVALID",
        "AUDIENCE_INVALID": "AUDIENCE_INVALID",
        "ROLE_INSUFFICIENT": "ROLE_INSUFFICIENT"
      };

      // Simula resposta do JwtValidator
      const jwtValidatorResponse = {
        status: 403,
        errorKey: "ROLE_INSUFFICIENT" as const
      };

      const errorKey = errorMapping[jwtValidatorResponse.errorKey];
      const catalogEntry = defaultErrorCatalog[errorKey];

      const problemDetails: ProblemDetails = {
        type: `https://errors.nstech.com.br/auth/${errorKey.toLowerCase()}`,
        title: catalogEntry.title,
        status: jwtValidatorResponse.status,
        detail: catalogEntry.detail,
        errorKey: errorKey,
        errorCode: catalogEntry.externalCode,
        instance: "/api/secure/resource",
        timestamp: new Date().toISOString()
      };

      expect(problemDetails.status).toBe(403);
      expect(problemDetails.errorKey).toBe("ROLE_INSUFFICIENT");
      expect(problemDetails.title).toBe("Permissão insuficiente");
    });

    it("deve suportar errorCode customizado do roleErrorMap", () => {
      const roleErrorMap = {
        "hub-agendamentos:admin": "HUB_FORBIDDEN_0007",
        "conta-digital:financeiro": "CD_FORBIDDEN_0101"
      };

      // Simula cenário onde o JwtValidator retorna um errorCode do roleErrorMap
      const errorResponse = {
        status: 403,
        errorKey: "ROLE_INSUFFICIENT" as const,
        errorCode: "HUB_FORBIDDEN_0007"
      };

      const catalogEntry = defaultErrorCatalog[errorResponse.errorKey];

      const problemDetails: ProblemDetails = {
        type: `https://errors.nstech.com.br/auth/${errorResponse.errorKey.toLowerCase()}`,
        title: catalogEntry.title,
        status: errorResponse.status,
        detail: catalogEntry.detail,
        errorKey: errorResponse.errorKey,
        errorCode: errorResponse.errorCode, // Usa o errorCode customizado
        instance: "/api/hub/agendamentos",
        timestamp: new Date().toISOString()
      };

      expect(problemDetails.errorCode).toBe("HUB_FORBIDDEN_0007");
      expect(problemDetails.errorKey).toBe("ROLE_INSUFFICIENT");
    });
  });
});