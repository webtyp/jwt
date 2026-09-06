---
PLAN: "feat(claims): expiry-aware DecodeUnverified outcome and an audience check helper"
EXECUTOR: jules
REVIEWER: none
---

> Este plan se despacha con el flujo CodeJob. Ver skill: `agents-workflow`.
> No ejecutes `gopush` ni `codejob` — son herramientas del desarrollador local.

# PLAN — `webtyp/jwt`: que el consumidor no tenga que acordarse

## Contexto

Auditoría de seguridad de `veltylabs/iam` (2026-09-02). `veltylabs/iam/client`
es la librería que cada proyecto Velty importa para hablarle al servicio de
identidad. Usa `DecodeUnverified` y después tiene que acordarse, por su cuenta,
de dos cosas que este paquete ya sabe: si el token venció y si su audiencia es
la esperada.

Doctrina obligatoria: [CONSTRUCTION_HARNESS.md](https://github.com/webtyp/app/blob/main/docs/CONSTRUCTION_HARNESS.md).
El principio que gobierna este plan:

- **"Things you *have to remember*. Any mandatory step the author must
  remember to call → that is a hole in the harness; close it with types or a
  single path, not with prose."**

Este es un plan chico y aditivo. **No cambia el comportamiento de `Verify` ni
de `Sign`**, que están bien: `Verify` recomputa HS256 sin leer nunca el `alg`
del header (evita la confusión de algoritmos), compara el MAC con
`hmac.HMACEqual` en tiempo constante, y `VerifyAny` recorre todos los secretos
sin salida temprana. Eso no se toca.

---

## Hallazgo J-1 (Bajo) · `DecodeUnverified` exige `exp` pero no lo mira

```go
func DecodeUnverified(token string) (Claims, error) {
	...
	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, fmt.Err("jwt", "decode", "missing-claims")
	}
	return c, nil
}
```

Exige que `exp` exista, y después no lo compara con la hora. Un token vencido
sale por la puerta con `err == nil`.

El uso real en `veltylabs/iam/client/client.go` es legítimo — la respuesta
viene de `iam` por la misma llamada HTTPS, así que la firma no aporta nada
nuevo — pero el llamador termina escribiendo:

```go
ctx.SetUserID(id.Claims.Sub)
c.cache.Set(id.Claims.Sub, id.Claims.Scope, id.Claims.Exp)
```

sin comparar `Exp` con la hora. El caché sí lo compara después, pero
`SetUserID` ya autenticó al llamante. Un `exp` en el pasado autentica igual.

Que ese caso sea inofensivo hoy no cambia el diagnóstico: la API deja que el
llamador se olvide de un chequeo, y por lo tanto se olvidó.

## Hallazgo J-2 (Bajo) · No hay forma de verificar la audiencia

`Claims` tiene `Aud` desde que `veltylabs/iam` emite tokens acotados a un
proyecto, pero no hay ningún helper que responda *"¿este token es para mí?"*.
El consumidor lo compara a mano, o no lo compara. En `iam/client` no lo
compara: `FetchAuthzToken` pide un token para `projectID` y nunca verifica que
el `Aud` que volvió sea ese.

---

## Etapa 1 · `Claims.Expired` y `Claims.AllowsAudience`

Archivo: `jwt.go`. Métodos nuevos sobre `Claims`, ambos puros.

```go
// Expired reporta si el token ya venció, con la misma tolerancia de reloj
// (Leeway) que usa Verify — para que un token que Verify llamaría vigente no
// sea "vencido" acá por unos segundos de deriva.
//
// Existe porque DecodeUnverified no puede negarse a devolver un token
// vencido (su trabajo es decodificar, no juzgar) pero el llamador SÍ tiene
// que preguntarlo. Tener el método hace que olvidarse sea visible en la
// revisión: un uso de DecodeUnverified sin un Expired cerca es sospechoso.
func (c Claims) Expired() bool

// AllowsAudience reporta si el token está acotado a aud. Un token sin Aud
// ("" = identidad sola, sin alcance) NO satisface ninguna audiencia
// concreta: pedir una audiencia y aceptar un token que no declara ninguna es
// el mismo error que aceptar un token de otro proyecto.
//
// aud == "" pregunta "¿es un token de identidad sola?" y sólo es cierto para
// un token sin Aud.
func (c Claims) AllowsAudience(aud string) bool
```

`Expired` usa `now() > c.Exp+Leeway`, exactamente la misma expresión que
`verifyWithPayload`. **Extraé esa comparación a una función no exportada
`isExpired(exp int64) bool` y llamala desde los dos sitios** — hoy la regla de
vencimiento vive en un solo lugar y tiene que seguir viviendo en uno solo
(principio 4: una sola forma de hacer cada cosa).

`AllowsAudience` compara con `==`. No es un secreto y no hay nada que filtrar
por tiempo; **no** uses `hmac.HMACEqual` acá — sería ruido criptográfico sobre
un identificador público.

## Etapa 2 · `DecodeUnverified` reporta el vencimiento

Cambiar la firma **rompe a los consumidores**, y el único chequeo que falta se
resuelve con la Etapa 1. Así que `DecodeUnverified` **no cambia de firma**.
Lo que cambia es su documentación, que hoy no menciona el vencimiento:

```go
// DecodeUnverified lee los claims SIN comprobar la firma. El token es entrada
// NO CONFIABLE: tratá el resultado como una pista para mostrar, nunca como
// una decisión de autorización.
//
// Tampoco comprueba el VENCIMIENTO: exige que exp exista, pero un exp en el
// pasado sale igual con err == nil. Si vas a usar estos claims para algo más
// que mostrarlos, preguntá Claims.Expired() — no hay un camino que lo haga
// por vos, porque decodificar y juzgar son trabajos distintos.
```

Y agregá el helper que sí junta las dos cosas, para el consumidor que quiere
un solo paso:

```go
// DecodeFresh es DecodeUnverified más el chequeo de vencimiento: devuelve
// ErrExpiredToken si el token ya venció. Sigue SIN comprobar la firma — es
// para el caso en que el canal ya prueba el origen (una respuesta que vino
// por la misma llamada HTTPS al emisor), no para un token que un tercero
// presenta.
func DecodeFresh(token string) (Claims, error)
```

Error nuevo:

```go
// ErrExpiredToken: el token es legible y bien formado, pero su exp ya pasó.
// Es un error y no un Outcome porque DecodeFresh no comprueba la firma: sin
// firma verificada no hay veredicto sobre autenticidad que dar, y mezclar los
// dos canales es lo que Outcome existe para evitar.
var ErrExpiredToken = fmt.Err("jwt", "token", "expired")
```

Mensaje exacto: `jwt token expired`.

## Etapa 3 · Tests

Archivo: `tests/claims_test.go` (nuevo; los tests del repo viven bajo `tests/`).

| Test | Fija |
|---|---|
| `TestClaimsExpiredPast` | `Exp` en el pasado más allá de `Leeway` → `true` |
| `TestClaimsExpiredWithinLeeway` | `Exp` vencido hace `Leeway-1` segundos → `false` |
| `TestClaimsExpiredFuture` | `Exp` futuro → `false` |
| `TestClaimsExpiredMatchesVerify` | Un token cuyo `Verify` da `Valid` tiene `Expired() == false`, y uno cuyo `Verify` da `Expired` tiene `Expired() == true`. **Ata las dos reglas de vencimiento entre sí.** |
| `TestAllowsAudienceExact` | `Aud: "proj-1"` → `AllowsAudience("proj-1") == true` |
| `TestAllowsAudienceRejectsOther` | `Aud: "proj-1"` → `AllowsAudience("proj-2") == false` |
| `TestAllowsAudienceRejectsUnscoped` | `Aud: ""` → `AllowsAudience("proj-1") == false`. **El caso peligroso.** |
| `TestAllowsAudienceIdentityOnly` | `Aud: ""` → `AllowsAudience("") == true` |
| `TestDecodeFreshRejectsExpired` | Token vencido → `ErrExpiredToken`, `Claims` cero |
| `TestDecodeFreshAcceptsValid` | Token vigente → claims completos, `err == nil` |
| `TestDecodeFreshDoesNotVerifySignature` | Token con la firma manipulada pero vigente → `err == nil`. **Documenta que sigue sin verificar firma; si alguien "arregla" eso, este test lo dice.** |
| `TestDecodeUnverifiedStillReturnsExpired` | Regresión: `DecodeUnverified` sobre un token vencido sigue devolviendo `err == nil`. **No cambiamos su contrato.** |

Y una regresión explícita de lo que **no** se toca:

| `TestUnscopedClaimsStillByteIdentical` | Un `Claims` sin `Aud` ni `Scope` se serializa exactamente igual que antes de este plan (los campos se omiten, no salen como `""`/`[]`). El repo ya tiene un test así — verificá que sigue verde y no lo borres. |

**Test consumer-shaped obligatorio** (regla de oro del harness: *an API is not
published until a consumer-shaped test, inside the library itself, proves it*).
En `tests/claims_test.go`:

```
TestConsumerValidatesAProjectScopedToken
```

Debe reproducir el uso de `veltylabs/iam/client`: firmar un token con
`NewScopedClaims(sub, "proj-1", []string{"admin"}, ttl)`, decodificarlo con
`DecodeFresh`, y afirmar en tres líneas que (a) no venció, (b)
`AllowsAudience("proj-1")` es `true`, (c) `AllowsAudience("proj-2")` es
`false`. Si esas tres preguntas no se responden con tres llamadas obvias, el
harness no está cerrado.

## Restricciones de código (leer antes de escribir)

| Regla | Detalle |
|---|---|
| **No toques `Verify`, `VerifyAny` ni `Sign`** | Están auditados y correctos. En particular: `Verify` **nunca** debe leer el campo `alg` del header — hacerlo es la vulnerabilidad de confusión de algoritmos. El comentario que lo prohíbe se queda. |
| **Sin mapas** | Prohibido `map[K]V` en librería y en tests. Slices + búsqueda lineal. |
| **Sin stdlib** | Nada de `fmt`, `errors`, `strconv`, `strings`, `time`, `log`, `os`, `encoding/json`. Usa `webtyp.com/fmt`, `webtyp.com/time`, `webtyp.com/json`. |
| **`error` sí, `errors` no** | `fmt.Err(...)`, nunca `errors.New`. |
| **Sin `reflect`** | Ni transitivo. |
| **Sin literales repetidos** | Todo string repetido es una constante nombrada. |
| **Sin `internal/`** | No crees carpetas `internal/`. |
| **Una sola regla de vencimiento** | `isExpired` es la única expresión que compara `Exp` con la hora. `verifyWithPayload` y `Claims.Expired` la llaman; ninguno la reescribe. |

Idioma: **código e identificadores en inglés**; **comentarios de prosa y
documentación en español**.

## Etapa 4 · Documentación

- `docs/SECURITY_AUDIT.md` (ya existe): agregar una entrada con fecha
  2026-09-02 registrando J-1 y J-2, qué se agregó y qué se decidió **no**
  cambiar (`DecodeUnverified` conserva su firma y su contrato).
- `README.md`: tabla "quiero X → uso Y":

  | Quiero | Uso |
  |---|---|
  | Autenticar un token que me presenta un tercero | `Verify(secret, token)` |
  | Lo mismo durante una rotación de secreto | `VerifyAny(secrets, token)` |
  | Leer un token que ya vino por un canal confiable | `DecodeFresh(token)` |
  | Sólo mostrar datos de un token, sin decidir nada | `DecodeUnverified(token)` |
  | Saber si venció | `claims.Expired()` |
  | Saber si es para mi proyecto | `claims.AllowsAudience(projectID)` |

## Criterios de aceptación

1. `go vet ./...` y `go test ./...` verdes.
2. `GOOS=js GOARCH=wasm go build ./...` compila.
3. `git diff jwt.go` no modifica los cuerpos de `Sign`, `Verify` ni
   `VerifyAny` salvo por la extracción de `isExpired`.
4. `grep -rn "now() > c.Exp" jwt.go` → una sola ocurrencia, dentro de `isExpired`.
5. `grep -rn "map\[" *.go` → vacío.
6. `Claims.Expired`, `Claims.AllowsAudience`, `DecodeFresh`, `ErrExpiredToken`
   exportados y documentados en español.
7. `TestConsumerValidatesAProjectScopedToken` existe y pasa.
8. Ningún consumidor queda roto: no hay cambios de firma.

## Etapas

| # | Archivos | Entrega |
|---|---|---|
| 1 | `jwt.go` | `isExpired`, `Claims.Expired`, `Claims.AllowsAudience` |
| 2 | `jwt.go` | `DecodeFresh`, `ErrExpiredToken`, doc de `DecodeUnverified` |
| 3 | `tests/claims_test.go` | Tests + consumer-shaped |
| 4 | `docs/SECURITY_AUDIT.md`, `README.md` | Registro de auditoría y tabla de uso |
