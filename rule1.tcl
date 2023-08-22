#
# iRule para assinar JWTs saindo da nossa infra
# e validar JWTs entrando
#
# Autor: Danilo B. de Araújo em 2023-08-22
# Alterado por / em: --
#
# Header: Authorization
#
# Docs:
# iRules: https://clouddocs.f5.com/api/irules/
# Priority: https://clouddocs.f5.com/api/irules/priority.html
# Crypto Sign: https://clouddocs.f5.com/api/irules/CRYPTO__sign.html
# Tcl Expressions: https://community.f5.com/t5/technical-articles/irules-101-02-if-and-expressions/ta-p/283431
#
# F5 BIG-IP Script Deployment: https://techdocs.f5.com/kb/en-us/products/big-iq-centralized-mgmt/manuals/product/bigiq-central-mgmt-device-5-4-0/4.html
#
#
proc signdata { token } {
  # Atenção: hardcoded secret key
  return [b64encode [CRYPTO::sign -alg hmac-sha1 -key "oNYV7EIiQ8qIALI/mk73Sg" $token]]
}

when HTTP_RESPONSE priority 1 {
  # Recupera o headers "Authorization"
  set authorization [HTTP::header "Authorization"]
  if {      
    ($authorization ne "")
  } then {
    # Assina token de saída (se existente) para ser verificado na entrada (retorno do JWT)

    # Calcula a assinatura
    set signature [signData $authorization]

    # Escreve no header "Msign"
    HTTP::header replace "Msign" $signature
  }
}

when HTTP_REQUEST priority 1 {
  # Em testes, limitar atuação apenas ao corporativo e ao SGSI
  if { 
    ([HTTP::path] starts_with "/corporativo_api" || [HTTP::path] starts_with "/sgsi")
  } then {
    # Recupera os headers "Authorization" e "Msign"
    set msign [HTTP::header "Msign"]
    set authorization [HTTP::header "Authorization"]

    if {
      ($authorization ne "")
    } then {
      # Valida assinatura do token de entrada (se existente) que foi assinado na saida

      if {
        ($msign eq "")
      } then {
        # Assinatura do header "Authorization" vazia
        # Cancela o request
        HTTP::close
      }

      # Calcula a assinatura
      set signature [signdata $authorization]

      if {
        ($msign ne $signature)
      } then {
        # Assinatura do header "Authorization" inválida
        # Cancela o request
        HTTP::close
      }
    }
  }
}
