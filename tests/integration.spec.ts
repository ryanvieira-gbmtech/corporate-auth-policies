// tests/integration.spec.ts
import { describe, it, expect, vi } from "vitest";
import { JwtValidator } from "../src/JwtValidator";
import { defaultErrorCatalog } from "../src/ProblemDetails";
import type { KeycloakJwtPayload } from "../src/types";
import { createMockReq, createMockRes, createMockNext } from "./testUtils";

describe("Integração - JwtValidator com ProblemDetails e Types", () => {
  it("deve converter erro do JwtValidator para ProblemDetails corretamente", async () => {
    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer"
    });

    const req = createMockReq(); // Sem token
    const { res, getJson } = createMockRes();
    const next = createMockNext();

    const middleware = validator.validateAudience("hub");
    await middleware(req, res, next);

    // Verifica resposta do JwtValidator
    expect(res.statusCode).toBe(401);
    const response = getJson();
    expect(response).toEqual({
      status: 401,
      errorKey: "TOKEN_NOT_PROVIDED"
    });

    // Converte para ProblemDetails usando o catálogo
    const errorKey = response.errorKey;
    const catalogEntry = defaultErrorCatalog[errorKey];

    const problemDetails = {
      type: `https://errors.nstech.com.br/auth/${errorKey.toLowerCase()}`,
      title: catalogEntry.title,
      status: response.status,
      detail: catalogEntry.detail,
      errorKey: errorKey,
      errorCode: catalogEntry.externalCode,
      instance: req.originalUrl,
      timestamp: expect.any(String) // Será gerado dinamicamente
    };

    expect(catalogEntry.title).toBe("Token não fornecido");
    expect(catalogEntry.httpStatus).toBe(401);
    expect(catalogEntry.externalCode).toBe("SEC-401-001");
  });

  it("deve integrar roleErrorMap com ProblemDetails", async () => {
    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer",
      roleErrorMap: {
        "hub-agendamentos:admin": "HUB_FORBIDDEN_0007",
        "conta-digital:financeiro": "CD_FORBIDDEN_0101"
      }
    });

    const mockPayload: KeycloakJwtPayload = {
      sub: "user-123",
      resource_access: {
        "hub-agendamentos": {
          roles: ["viewer"] // Não tem admin
        }
      }
    };

    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

    const req = createMockReq({
      headers: {
        authorization: "Bearer token"
      }
    });
    const { res, getJson } = createMockRes();
    const next = createMockNext();

    const middleware = validator.validateRole("hub-agendamentos", "admin");
    await middleware(req, res, next);

    // Verifica resposta
    expect(res.statusCode).toBe(403);
    const response = getJson();
    expect(response).toEqual({
      status: 403,
      errorKey: "ROLE_INSUFFICIENT",
      errorCode: "HUB_FORBIDDEN_0007"
    });

    // Combina com catálogo padrão
    const catalogEntry = defaultErrorCatalog[response.errorKey];
    
    const problemDetails = {
      type: `https://errors.nstech.com.br/auth/${response.errorKey.toLowerCase()}`,
      title: catalogEntry.title,
      status: response.status,
      detail: catalogEntry.detail,
      errorKey: response.errorKey,
      errorCode: response.errorCode, // Usa o customizado do roleErrorMap
      instance: req.originalUrl
    };

    expect(problemDetails.title).toBe("Permissão insuficiente");
    expect(problemDetails.errorCode).toBe("HUB_FORBIDDEN_0007");
  });

  it("deve usar tipos corretos em todo o fluxo", async () => {
    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer"
    });

    // Mock com tipo KeycloakJwtPayload
    const mockPayload: KeycloakJwtPayload = {
      sub: "user-123",
      aud: "hub-agendamentos",
      resource_access: {
        "hub-agendamentos": {
          roles: ["admin"]
        }
      }
    };

    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

    const req = createMockReq({
      headers: {
        authorization: "Bearer valid-token"
      }
    });
    const { res } = createMockRes();
    const next = createMockNext();

    const middleware = validator.validateAudience("hub-agendamentos");
    await middleware(req, res, next);

    // Verifica que o user foi populado com tipos corretos
    expect((req as any).user).toEqual({
      id: "user-123"
    });

    // Agora testa validateRole
    const roleMiddleware = validator.validateRole("hub-agendamentos", "admin");
    
    // Precisamos mockar novamente para o segundo middleware
    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);
    
    await roleMiddleware(req, res, next);

    expect((req as any).user.roles).toEqual(["admin"]);
  });

  it("deve lidar com múltiplos clients no resource_access", async () => {
    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer"
    });

    const mockPayload: KeycloakJwtPayload = {
      sub: "user-multi",
      resource_access: {
        "hub-agendamentos": {
          roles: ["admin", "viewer"]
        },
        "conta-digital": {
          roles: ["financeiro", "gerente"]
        },
        "hub-financeiro": {
          roles: ["contador", "auditor"]
        }
      }
    };

    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

    const req = createMockReq({
      headers: {
        authorization: "Bearer token"
      }
    });
    const { res } = createMockRes();
    const next = createMockNext();

    // Testa validação para diferentes clients
    const middleware1 = validator.validateRole("hub-agendamentos", "admin");
    await middleware1(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect((req as any).user.roles).toEqual(["admin", "viewer"]);

    next.mockClear();
    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

    const middleware2 = validator.validateRole("conta-digital", "gerente");
    await middleware2(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect((req as any).user.roles).toEqual(["financeiro", "gerente"]);

    next.mockClear();
    validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

    const middleware3 = validator.validateRole("hub-financeiro", "contador");
    await middleware3(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect((req as any).user.roles).toEqual(["contador", "auditor"]);
  });
});