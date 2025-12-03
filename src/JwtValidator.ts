// src/JwtValidator.ts - Vamos refatorar para melhor testabilidade
import type { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload, JwtHeader } from "jsonwebtoken";
import jwksClient, { SigningKey } from "jwks-rsa";

type RoleErrorMap = Record<string, string>;

export interface JwtValidatorOptions {
  jwksUri: string;
  issuer: string;
  roleErrorMap?: RoleErrorMap;
}

export class JwtValidator {
  private client;
  private issuer: string;
  private roleErrorMap: RoleErrorMap;

  constructor(options: JwtValidatorOptions) {
    this.client = jwksClient({
      jwksUri: options.jwksUri,
    });
    this.issuer = options.issuer;
    this.roleErrorMap = options.roleErrorMap ?? {};
  }

  // Expor método público para testes
  public extractToken(req: Request): string | null {
    const auth =
      (req.headers["authorization"] ||
        (req.headers["Authorization"] as string | undefined)) ?? "";

    if (!auth.startsWith("Bearer ")) return null;
    return auth.substring("Bearer ".length);
  }

  // Expor método público para testes
  public async verifyToken(token: string): Promise<JwtPayload> {
    return new Promise<JwtPayload>((resolve, reject) => {
      jwt.verify(
        token,
        (header: JwtHeader, callback) => {
          this.client.getSigningKey(
            header.kid as string,
            (err: Error | null, key?: SigningKey) => {
              if (err) return callback(err);
              const signingKey = key!.getPublicKey();
              callback(null, signingKey);
            }
          );
        },
        {
          issuer: this.issuer,
          algorithms: ["RS256"],
        },
        (err, decoded) => {
          if (err || !decoded) {
            const e: any = err || new Error("TOKEN_INVALID");
            e.code = "TOKEN_INVALID";
            return reject(e);
          }
          resolve(decoded as JwtPayload);
        }
      );
    });
  }

  validateAudience(expectedAudience: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
      const token = this.extractToken(req);

      if (!token) {
        return res.status(401).json({
          status: 401,
          errorKey: "TOKEN_NOT_PROVIDED",
        });
      }

      try {
        const decoded = await this.verifyToken(token);

        const aud = decoded.aud;
        const audStr = Array.isArray(aud) ? aud[0] : aud;

        if (!audStr || audStr !== expectedAudience) {
          return res.status(403).json({
            status: 403,
            errorKey: "AUDIENCE_INVALID",
            detail: `Expected audience '${expectedAudience}', got '${audStr ?? "undefined"}'`,
          });
        }

        (req as any).user = {
          ...(req as any).user,
          id: decoded.sub,
        };

        return next();
      } catch (err: any) {
        if (err.code === "TOKEN_INVALID") {
          return res.status(403).json({
            status: 403,
            errorKey: "TOKEN_INVALID",
          });
        }
        
        // Erro inesperado
        return res.status(500).json({
          status: 500,
          errorKey: "INTERNAL_ERROR",
        });
      }
    };
  }

  validateRole(clientId: string, requiredRole: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
      const token = this.extractToken(req);

      if (!token) {
        return res.status(401).json({
          status: 401,
          errorKey: "TOKEN_NOT_PROVIDED",
        });
      }

      try {
        const decoded = await this.verifyToken(token);

        const resourceAccess = (decoded as any).resource_access ?? {};
        const client = resourceAccess[clientId] ?? {};
        const roles: string[] = client.roles ?? [];

        if (!roles.includes(requiredRole)) {
          const key = `${clientId}:${requiredRole}`;
          const errorCode = this.roleErrorMap[key];

          return res.status(403).json({
            status: 403,
            errorKey: "ROLE_INSUFFICIENT",
            errorCode,
          });
        }

        (req as any).user = {
          ...(req as any).user,
          id: decoded.sub,
          roles,
        };

        return next();
      } catch (err: any) {
        if (err.code === "TOKEN_INVALID") {
          return res.status(403).json({
            status: 403,
            errorKey: "TOKEN_INVALID",
          });
        }
        
        return res.status(500).json({
          status: 500,
          errorKey: "INTERNAL_ERROR",
        });
      }
    };
  }
}