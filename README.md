# Máscara de Dados (LGPD)

> Mascara CPF, CNPJ, e-mail, telefone e cartão em textos e objetos antes de gravar log, e troca senha, token e authorization por [REDACTED]. Logs úteis sem vazar dado pessoal.

**Ver ao vivo, com preview e manual:** https://flowcoresolucoes.com.br/codigos/mascarar-dados-lgpd

Criado por **FlowCore Soluções LTDA**.

## Arquivos

- [`src/mascarar-lgpd.ts`](src/mascarar-lgpd.ts)
- [`src/mascarar-lgpd.test.ts`](src/mascarar-lgpd.test.ts)

## Como instalar

1. **Funciona onde você já roda** Node 18+, Cloudflare Workers, Deno, Bun, Vercel e Netlify Functions. Zero dependência: só fetch e Web Crypto, que já vêm no runtime.
2. **Crie src/lib/mascarar-lgpd.ts** Copie o conteúdo de `src/mascarar-lgpd.ts` e `src/mascarar-lgpd.test.ts` deste repositório.
3. **Use**

   ```bash
   mascararTexto("CPF 529.982.247-25, tel (11) 98765-4321");
   // "CPF ***.982.247-**, tel (11) *****-4321"
   logger.info(mascararObjeto({ usuario, headers: req.headers, body }));
   ```

4. **Rode o teste junto** O arquivo de teste (`src/mascarar-lgpd.test.ts`) cobre 9 cenários. Copie para src/lib/ ao lado e rode:

   ```bash
   npm install -D vitest
   npx vitest run src/lib
   ```


## Testes

`src/mascarar-lgpd.test.ts` cobre 9 cenários.

```bash
npm install
npm test
```

## Licença

MIT. Pode usar em projeto pessoal ou comercial, de graça. A única condição é manter a linha **“Criado por FlowCore Soluções LTDA”** (ou o crédito de adaptação) onde ela está.

---

Precisa disso integrado no seu sistema? A [FlowCore](https://flowcoresolucoes.com.br) desenvolve sob medida.
