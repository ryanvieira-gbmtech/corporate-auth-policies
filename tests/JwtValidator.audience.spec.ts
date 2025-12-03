// tests/JwtValidator.audience.spec.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { JwtValidator } from "../src/JwtValidator";
import { createMockReq, createMockRes, createMockNext } from "./testUtils";

describe("JwtValidator - Validação de Audience", () => {
  let validator: JwtValidator;

  beforeEach(() => {
    validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer"
    });
  });

  describe("Casos de sucesso (status 200)", () => {
    it("deve manter status 200 e chamar next quando token é válido e audience corresponde", async () => {
      const mockPayload = {
        sub: "user-123",
        aud: "hub"
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer valid-token"
        }
      });
      const { res } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect((req as any).user).toEqual({
        id: "user-123"
      });
      expect(res.json).not.toHaveBeenCalled();
    });

    it("deve manter status 200 com audience como array", async () => {
      const mockPayload = {
        sub: "user-456",
        aud: ["hub", "outro-client"]
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer valid-token"
        }
      });
      const { res } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect((req as any).user.id).toBe("user-456");
    });

    it("deve manter status 200 quando já existe user no request", async () => {
      const mockPayload = {
        sub: "user-789",
        aud: "hub"
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer valid-token"
        }
      });
      
      (req as any).user = {
        email: "test@example.com",
        name: "Test User"
      };
      
      const { res } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(200);
      expect(next).toHaveBeenCalledTimes(1);
      expect((req as any).user).toEqual({
        email: "test@example.com",
        name: "Test User",
        id: "user-789"
      });
    });

  

  });

  describe("Fluxos de erro", () => {
    it("deve retornar 401 quando token não é fornecido", async () => {
      const req = createMockReq();
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(401);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(getJson()).toEqual({
        status: 401,
        errorKey: "TOKEN_NOT_PROVIDED"
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("deve retornar 403 quando audience não corresponde", async () => {
      const mockPayload = {
        sub: "user-123",
        aud: "outro-client"
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "AUDIENCE_INVALID",
        detail: "Expected audience 'hub', got 'outro-client'"
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

      const middleware = validator.validateAudience("hub");
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

      const middleware = validator.validateAudience("hub");
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
    it("deve lidar com audience undefined", async () => {
      const mockPayload = {
        sub: "user-123"
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "AUDIENCE_INVALID",
        detail: "Expected audience 'hub', got 'undefined'"
      });
    });

    it("deve lidar com audience vazia", async () => {
      const mockPayload = {
        sub: "user-123",
        aud: ""
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "AUDIENCE_INVALID",
        detail: "Expected audience 'hub', got ''"
      });
    });

    it("deve lidar com audience como array vazio", async () => {
      const mockPayload = {
        sub: "user-123",
        aud: []
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "AUDIENCE_INVALID",
        detail: "Expected audience 'hub', got 'undefined'"
      });
    });

    it("deve lidar com audience como array que não contém o esperado", async () => {
      const mockPayload = {
        sub: "user-123",
        aud: ["client1", "client2"]
      };

      validator.verifyToken = vi.fn().mockResolvedValue(mockPayload);

      const req = createMockReq({
        headers: {
          authorization: "Bearer token"
        }
      });
      const { res, getJson } = createMockRes();
      const next = createMockNext();

      const middleware = validator.validateAudience("hub");
      await middleware(req, res, next);

      expect(res.statusCode).toBe(403);
      expect(getJson()).toEqual({
        status: 403,
        errorKey: "AUDIENCE_INVALID",
        detail: "Expected audience 'hub', got 'client1'"
      });
    });
  });
});