# Generate Certificate Chain


```bash
-a ca-certs 
-i input.txt
-o ca-certs
```

# Generate CRLs

```bash
-a ca-crls
-i ca-certs
-o ca-crls
```

# Sample input.txt

Lines starting with # will be ignored

```
#P7B|http://www.downloadcertisign.com.br/site/Hierarquias/ICP_Brasil/hierarquia-completa/ICP-V2c.p7b
P7B|http://www.validcertificadora.com.br/certificados_hierarquia/ACVALIDBrasil.p7b
P7B|http://www.validcertificadora.com.br/certificados_hierarquia/AC_VALID_JUS/ac-validjusv2.p7b
P7B|http://www.validcertificadora.com.br/certificados_hierarquia/AC_VALID_PLUS/ac-validplusv2.p7b
P7B|http://www.validcertificadora.com.br/certificados_hierarquia/ACVALIDRFB.p7b
P7S|http://ccd.acsoluti.com.br/cadeias/ac-soluti-multipla-v1.pem
P7S|http://ccd.acsoluti.com.br/cadeias/ac-soluti-multipla-v5.pem
#ZIP|http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip
ZIP|https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip
PEM|https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv6.crt
PEM|https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv7.crt
PEM|https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt
PEM|https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv11.crt
#PEM|https://curl.haxx.se/ca/cacert.pem
#PEM|https://letsencrypt.org/certs/isrgrootx1.pem
#PEM|https://letsencrypt.org/certs/isrg-root-x2.pem
#PEM|https://letsencrypt.org/certs/lets-encrypt-r3.pem
#PEM|https://letsencrypt.org/certs/lets-encrypt-e1.pem
```