// tests/JwtValidator.role.spec.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { JwtValidator } from "../src/JwtValidator";
import { createMockReq, createMockRes, createMockNext } from "./testUtils";

describe("JwtValidator - Validação de Roles", () => {
  let validator: JwtValidator;

  beforeEach(() => {
    validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer"
    });
  });

  describe("Casos de sucesso (status 200)", () => {
    it("deve manter status 200 e chamar next quando role existe", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: ["admin", "viewer"]
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

      const middleware = validator.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect((req as any).user).toEqual({
        id: "user-123",
        roles: ["admin", "viewer"]
      });
      expect(res.json).not.toHaveBeenCalled();
    });

    it("deve manter status 200 com múltiplas roles", async () => {
      const mockPayload = {
        sub: "user-456",
        resource_access: {
          "conta-digital": {
            roles: ["financeiro", "gerente", "consultor"]
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

      const middleware = validator.validateRole("conta-digital", "gerente");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect((req as any).user.roles).toEqual(["financeiro", "gerente", "consultor"]);
    });

    it("deve manter status 200 quando já existe user no request", async () => {
      const mockPayload = {
        sub: "user-789",
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
      
      (req as any).user = {
        email: "admin@example.com",
        name: "Admin User"
      };
      
      const { res } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect((req as any).user).toEqual({
        email: "admin@example.com",
        name: "Admin User",
        id: "user-789",
        roles: ["admin"]
      });
    });

    it("deve manter status 200 para diferentes estruturas de roles", async () => {
      const testCases = [
        {
          resource_access: {
            "hub-agendamentos": { roles: ["admin"] }
          },
          clientId: "hub-agendamentos",
          requiredRole: "admin"
        },
        {
          resource_access: {
            "hub-agendamentos": { roles: ["viewer", "editor", "admin"] }
          },
          clientId: "hub-agendamentos",
          requiredRole: "editor"
        },
        {
          resource_access: {
            "hub-agendamentos": { roles: ["viewer"] },
            "conta-digital": { roles: ["admin", "financeiro"] }
          },
          clientId: "conta-digital",
          requiredRole: "financeiro"
        }
      ];

      for (const testCase of testCases) {
        validator.verifyToken = vi.fn().mockResolvedValue({
          sub: "user-test",
          ...testCase
        });

        const req = createMockReq({
          headers: {
            authorization: "Bearer valid-token"
          }
        });
        const { res } = createMockRes();
        const next = createMockNext();

        const middleware = validator.validateRole(testCase.clientId, testCase.requiredRole);
        await middleware(req, res, next);

        expect(res.statusCode).toBe(200);
        expect(next).toHaveBeenCalledTimes(1);
        
        // Limpar mocks para próximo teste
        vi.clearAllMocks();
      }
    });
  });

  describe("Fluxos de erro", () => {
    it("deve retornar 401 quando token não é fornecido", async () => {
      const req = createMockReq();
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(401);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(getJson()).toEqual({
        status: 401,
        errorKey: "TOKEN_NOT_PROVIDED"
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("deve retornar 403 quando role não existe", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: ["viewer"]
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

      expect(res.statusCode).toBe(403);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("deve retornar 403 com errorCode do roleErrorMap quando configurado", async () => {
      const validatorWithErrorMap = new JwtValidator({
        jwksUri: "https://fake/jwks",
        issuer: "https://fake/issuer",
        roleErrorMap: {
          "hub-agendamentos:admin": "HUB_FORBIDDEN_0007",
          "conta-digital:financeiro": "CD_FORBIDDEN_0101"
        }
      });

      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: ["viewer"]
          }
        }
      };

      validatorWithErrorMap.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validatorWithErrorMap.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT",
        errorCode: "HUB_FORBIDDEN_0007"
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("deve retornar 403 quando token é inválido", async () => {
      const error = new Error("Token inválido");
      (error as any).code = "TOKEN_INVALID";
      
      validator.verifyToken = vi.fn().mockRejectedValue(error);

      const req = createMockReq({
        headers: {
          authorization: "Bearer invalid-token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "TOKEN_INVALID"
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("deve retornar 500 para erros inesperados", async () => {
      const error = new Error("Erro inesperado");
      
      validator.verifyToken = vi.fn().mockRejectedValue(error);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateRole("hub-agendamentos", "admin");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(500);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(getJson()).toEqual({
        status: 500,
        errorKey: "INTERNAL_ERROR"
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("Casos edge", () => {
    it("deve lidar com resource_access vazio", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {}
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });

    it("deve lidar com client não existente no resource_access", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "outro-client": {
            roles: ["admin"]
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });

    it("deve lidar com client sem roles", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            // sem roles
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });

    it("deve lidar com roles vazias", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: []
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });

    it("deve lidar sem resource_access no payload", async () => {
      const mockPayload = {
        sub: "user-123"
        // sem resource_access
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });

    it("deve lidar com resource_access undefined", async () => {
      const mockPayload = {
        sub: "user-123",
        resource_access: undefined
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

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
      });
    });
  });

  describe("roleErrorMap", () => {
    it("deve usar errorCode correto para cada combinação client:role", async () => {
      const validatorWithErrorMap = new JwtValidator({
        jwksUri: "https://fake/jwks",
        issuer: "https://fake/issuer",
        roleErrorMap: {
          "hub-agendamentos:admin": "HUB_FORBIDDEN_0001",
          "hub-agendamentos:editor": "HUB_FORBIDDEN_0002",
          "conta-digital:financeiro": "CD_FORBIDDEN_0101",
          "conta-digital:gerente": "CD_FORBIDDEN_0102"
        }
      });

      const testCases = [
        {
          clientId: "hub-agendamentos",
          requiredRole: "admin",
          expectedErrorCode: "HUB_FORBIDDEN_0001"
        },
        {
          clientId: "hub-agendamentos",
          requiredRole: "editor",
          expectedErrorCode: "HUB_FORBIDDEN_0002"
        },
        {
          clientId: "conta-digital",
          requiredRole: "financeiro",
          expectedErrorCode: "CD_FORBIDDEN_0101"
        },
        {
          clientId: "conta-digital",
          requiredRole: "gerente",
          expectedErrorCode: "CD_FORBIDDEN_0102"
        }
      ];

      for (const testCase of testCases) {
        const mockPayload = {
          sub: "user-123",
          resource_access: {
            [testCase.clientId]: {
              roles: ["viewer"] // não tem a role necessária
            }
          }
        };

        validatorWithErrorMap.verifyToken = vi.fn().mockResolvedValue(mockPayload);

        const req = createMockReq({
          headers: {
            authorization: "Bearer token"
          }
        });
        const { res, getJson } = createMockRes();
        const next = createMockNext();

        const middleware = validatorWithErrorMap.validateRole(testCase.clientId, testCase.requiredRole);
        await middleware(req, res, next);

        expect(res.statusCode).toBe(403);
        expect(getJson()).toEqual({
          status: 403,
          errorKey: "ROLE_INSUFFICIENT",
          errorCode: testCase.expectedErrorCode
        });
        
        // Limpar mocks para próximo teste
        vi.clearAllMocks();
      }
    });

    it("deve não incluir errorCode quando não há mapeamento", async () => {
      const validatorWithPartialErrorMap = new JwtValidator({
        jwksUri: "https://fake/jwks",
        issuer: "https://fake/issuer",
        roleErrorMap: {
          "hub-agendamentos:admin": "HUB_FORBIDDEN_0001"
          // sem mapeamento para editor
        }
      });

      const mockPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: ["viewer"] // não tem editor
          }
        }
      };

      validatorWithPartialErrorMap.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validatorWithPartialErrorMap.validateRole("hub-agendamentos", "editor");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "ROLE_INSUFFICIENT"
        // sem errorCode
      });
    });
  });
});