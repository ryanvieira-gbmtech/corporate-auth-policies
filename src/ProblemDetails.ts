// src/ProblemDetails.ts
export interface ProblemDetails {
  type?: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  errorKey?: ErrorKey;
  errorCode?: string;
  [key: string]: any;
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

export type ErrorCatalog = Record<ErrorKey, ErrorCatalogEntry>;

export const defaultErrorCatalog: ErrorCatalog = {
  TOKEN_NOT_PROVIDED: {
    httpStatus: 401,
    title: "Token não fornecido",
    detail: "O cabeçalho Authorization não foi enviado.",
    externalCode: "SEC-401-001"
  },
  TOKEN_INVALID: {
    httpStatus: 403,
    title: "Token inválido",
    detail: "O token não pôde ser validado.",
    externalCode: "SEC-403-001"
  },
  TOKEN_NOT_YET_VALID: {
    httpStatus: 403,
    title: "Token ainda não é válido",
    detail: "O token possui 'iat' maior que o horário atual.",
    externalCode: "SEC-403-002"
  },
  AUDIENCE_INVALID: {
    httpStatus: 403,
    title: "Audience inválida",
    detail: "O audience do token não corresponde ao esperado.",
    externalCode: "SEC-403-003"
  },
  ROLE_INSUFFICIENT: {
    httpStatus: 403,
    title: "Permissão insuficiente",
    detail: "A role exigida não foi encontrada no token.",
    externalCode: "SEC-403-004"
  },
  ROLE_MAPPING_NOT_FOUND: {
    httpStatus: 403,
    title: "Role não mapeada",
    detail: "Não há mapeamento externo configurado para essa role.",
    externalCode: "SEC-403-005"
  },
  INTERNAL_ERROR: {
    httpStatus: 500,
    title: "Erro interno",
    detail: "Falha inesperada ao validar o token.",
    externalCode: "SEC-500-001"
  }
};
