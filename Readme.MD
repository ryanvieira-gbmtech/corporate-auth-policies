# `@nstech/corporate-auth-policies`

Políticas corporativas de autenticação e autorização para aplicações Node.js/TypeScript usando JWT, JWKS e Keycloak — com respostas padronizadas seguindo **Problem Details (RFC 7807)** e os **ErrorCodes oficiais da NSTech**.

Se você já sofreu debugando token quebrado, audience zoada ou role que o Keycloak “jura que existe”… este pacote é para você.

---

## 1. Objetivo

Unificar, padronizar e tornar minimamente civilizado o tratamento de autenticação/autorização em APIs Node.js dentro da NSTech, usando:

* Validação de JWT assinado com RS256.
* Resolução automática de chaves públicas via JWKS.
* Middlewares Express para validar audiences e roles.
* Respostas sempre em formato Problem Details.
* Catálogo interno de erros (ErrorKey).
* Catálogo externo de códigos, via `errorCode`, conforme o padrão corporativo.
* De/para de role mapeável por domínio, porque cada produto tem sua lógica própria, claro.

Este pacote existe para que você não precise mais reinventar a roda de autenticação a cada sprint, nem precisar decifrar mensagens crípticas do Keycloak às 3 da manhã.

---

## 2. Instalação

```bash
npm install @nstech/corporate-auth-policies
```

Se for usar no registry interno:

```bash
npm install @nstech/corporate-auth-policies --registry=https://npm.nstech.com.br
```

---

## 3. Conceitos principais

### 3.1 O que este pacote faz

* Valida tokens JWT emitidos pelo Keycloak.
* Faz download da chave pública no padrão JWKS.
* Garante que o token está dentro do tempo válido.
* Verifica audience.
* Verifica roles por client.
* Responde erros sempre com Problem Details (RFC 7807).
* Expõe de/para corporativo via `errorCode`.

### 3.2 O que ele **não** faz

* Não mascara erros.
* Não adivinha roles.
* Não transforma má configuração de Keycloak em milagre.

Se algo for configurado errado, ele te diz. De forma educada. Mais ou menos.

---

## 4. Padrões oficiais da NSTech integrados

Este pacote segue estritamente:

### 4.1 Problem Details (RFC 7807)

Obrigatório para qualquer resposta HTTP de erro (4xx e 5xx), segundo:

[https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/problem-details-nstech](https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/problem-details-nstech)

Campos padrão usados:

```
type
title
status
detail
errorKey
errorCode
instance
timestamp
correlationId
```

### 4.2 HTTP Status Codes Oficiais

Todos os status retornados seguem a matriz oficial da arquitetura:

[https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/http-status-oficial](https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/http-status-oficial)

Exemplos aplicados internamente:

* 401 quando o token está ausente.
* 403 quando o token é inválido, incompleto ou role insuficiente.
* 500 quando você claramente fez algo feio.

### 4.3 ErrorCodes corporativos

Formato empresarial e elegante (ou doloroso, depende do humor):

```
<DOMINIO>_<CATEGORIA>_<CÓDIGO>
```

Exemplos usados no pacote:

```
AUTH_INVALID_0001
AUTH_FORBIDDEN_0002
CROSSDOMAIN_UNAUTHORIZED_0003
```

Você pode sobrescrever tudo via catálogo customizado.

---

## 5. Exemplo rápido

```ts
import express from "express";
import { JwtValidator } from "@nstech/corporate-auth-policies";

const app = express();

const auth = new JwtValidator({
  jwksUri: "https://keycloak.local/realms/master/protocol/openid-connect/certs",
  issuer: "https://keycloak.local/realms/master",
  roleErrorMap: {
    "hub-agendamentos:admin": "HUB_FORBIDDEN_0007"
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.get("/secure",
  auth.validateAudience("hub-agendamentos"),
  (req, res) => res.json({ message: "Access granted", user: req.user })
);

app.get("/secure/admin",
  auth.validateRole("hub-agendamentos", "admin"),
  (req, res) => res.json({ message: "Admin OK" })
);

app.listen(3000);
```

---

## 6. Exemplos de erros (Problem Details)

### 6.1 Token ausente

```
{
  "title": "Token não fornecido",
  "status": 401,
  "detail": "O cabeçalho Authorization não foi enviado.",
  "errorKey": "TOKEN_NOT_PROVIDED",
  "errorCode": "AUTH_UNAUTHORIZED_0001",
  "instance": "/secure",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

### 6.2 Audience inválida

```
{
  "title": "Audience inválida",
  "status": 403,
  "detail": "Esperado: hub-agendamentos",
  "errorKey": "AUDIENCE_INVALID",
  "errorCode": "AUTH_FORBIDDEN_0004"
}
```

### 6.3 Role insuficiente

```
{
  "title": "Permissão insuficiente",
  "status": 403,
  "detail": "Role 'admin' não encontrada",
  "errorKey": "ROLE_INSUFFICIENT",
  "errorCode": "HUB_FORBIDDEN_0007"
}
```

---

## 7. Configurações disponíveis

```ts
new JwtValidator({
  jwksUri: string,                 // obrigatório
  issuer?: string,                 // recomendado
  algorithms?: ["RS256"],          // default
  errorCatalog?: {...},            // substitui catálogo interno
  roleErrorMap?: {...}             // de/para externo para roles
});
```

### 7.1 roleErrorMap

Mapa simples:

```
"<audience>:<role>" → "<errorCode>"
```

Exemplo:

```
"conta-digital:financeiro": "CD_FORBIDDEN_0101"
```

Se quiser mapear 100 roles diferentes, bom… força.

---

## 8. Middlewares

### 8.1 `validateAudience(audience: string)`

Garante que o token contém a audience especificada.

### 8.2 `validateRole(audience: string, role: string)`

Garante que o usuário possui a role do client (`resource_access[audience].roles`).

Sim: funciona com Keycloak, com roles herdadas, diretas e com aplicações multi-tenant.

---

## 9. Estrutura de resposta corporativa (exemplo completo)

```
{
  "type": "https://errors.nstech.com.br/auth/forbidden",
  "title": "Permissão insuficiente",
  "status": 403,
  "detail": "Role 'admin' não encontrada",
  "errorKey": "ROLE_INSUFFICIENT",
  "errorCode": "AUTH_FORBIDDEN_0002",
  "instance": "/secure/admin",
  "timestamp": "2025-01-01T12:30:20Z",
  "correlationId": "8d8f0a89-3f8d-4e39-81ba-7fe21fbf5a81"
}
```

Se o usuário tentar forçar acesso, o erro pelo menos estará padronizado.
As decisões ruins ele resolve depois.

---

## 10. Testes e coberturas

Essa stack possui testes unitários, e possui uma cobertura boa de forma que esse garante o bom funcionamento, e solicitamos que seja mantido por habito ("🎶Pois quem gosta de nós somos nós mesmos🎶"), por cultivo de boas práticas e por qualidade de códigos.
---

## 11. Sobrevivendo ao Keycloak (Notas práticas)

* Sempre confira se você está usando o **client correto** na audience.
* Roles vivem em `resource_access[audience].roles`.
* Roles realm-wide ficam em `realm_access.roles`, mas este pacote foca em client roles.
* Se você não sabe qual role usar… provavelmente ninguém sabe. Boa sorte.

---

## 12. Referências internas

* HTTP Status Codes oficial NSTech
  [https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/http-status-oficial](https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/http-status-oficial)

* Problem Details NSTech
  [https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/problem-details-nstech](https://nsconecta.nstech.com.br/pt-br/architecture/how-to-use-statuscode/problem-details-nstech)

* Resiliência, Circuit Breaker e padrões de erro
  (vide área de arquitetura)

---

## 13. Contribuição

Pull requests são bem-vindos.
Pull requests sem testes, sem lint e sem contexto não são.
Se você mandar algo incompleto, eu vou responder “legal, mas falta metade”.
Com carinho.

---

## 14. Licença

MIT. Mas use com responsabilidade, porque MIT não cobre erros de Keycloak nem decisões arquiteturais ruins.
