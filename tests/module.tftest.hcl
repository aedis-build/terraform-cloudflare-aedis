# Plan do módulo sem credenciais nem rede: o provider é simulado e a zona vem do mock.
mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = {
      id      = "023e105f4ecef8ad9ca31a8372d0c353"
      account = { id = "f037e56e89293a057740de681ac9abbe" }
    }
  }
}

# A zona do aedis.build: dois sites estáticos e a cdn, no Free.
variables {
  zone_name = "aedis.build"
  workloads = {
    site = { type = "site-static", hostnames = ["aedis.build"] }
    ui   = { type = "site-static", hostnames = ["ui.aedis.build"] }
    cdn  = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "aedis-cdn", allowed_referers = ["aedis.build"] }
  }
}

run "free_dois_sites_estaticos_e_cdn" {
  command = plan

  assert {
    condition     = [for r in cloudflare_ruleset.custom[0].rules : r.ref] == ["aedis_methods", "aedis_cdn_hotlink"]
    error_message = "uma regra de métodos para a zona inteira e a de hotlink da cdn: 2 das 5 do Free"
  }
  assert {
    condition     = cloudflare_ruleset.custom[0].rules[0].expression == "(http.host in {\"cdn.aedis.build\" \"aedis.build\" \"ui.aedis.build\"} and not http.request.method in {\"GET\" \"HEAD\"})" && cloudflare_ruleset.custom[0].rules[0].action == "block"
    error_message = "site-static e cdn dividem o termo de GET e HEAD, com os hostnames de todos"
  }
  assert {
    condition     = length(cloudflare_ruleset.rate_limit[0].rules) == 1 && cloudflare_ruleset.rate_limit[0].rules[0].ref == "aedis_site_rate_limit" && cloudflare_ruleset.rate_limit[0].rules[0].expression == "http.host in {\"aedis.build\" \"ui.aedis.build\"} and not cf.client.bot"
    error_message = "sem forms, a única regra do Free é o limite geral nos sites, sem a cdn (o camo do GitHub) e sem bots verificados"
  }
  assert {
    condition     = cloudflare_ruleset.rate_limit[0].rules[0].action == "block" && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.mitigation_timeout == 10 && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.period == 10 && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.requests_per_period == 100
    error_message = "no Free o limite geral bloqueia (a única ação que o plano aceita) por 10 s, 100 por 10 s"
  }
  assert {
    condition     = length(cloudflare_ruleset.managed) == 0 && length(cloudflare_turnstile_widget.this) == 0 && length(cloudflare_email_routing_settings.this) == 0
    error_message = "o free não declara rulesets gerenciados; Turnstile e Email Routing só quando pedidos"
  }
  assert {
    condition     = cloudflare_bot_management.this.fight_mode == true && cloudflare_bot_management.this.ai_bots_protection == "disabled" && cloudflare_bot_management.this.crawler_protection == "disabled"
    error_message = "Bot Fight Mode ligado por padrão, regra legada de IA e labirinto desligados"
  }
  assert {
    condition     = cloudflare_bot_management.this.aisearch == "disabled" && cloudflare_bot_management.this.ai_user == "disabled" && cloudflare_bot_management.this.ai_training == "block"
    error_message = "política de IA padrão: busca e agente liberados, treino bloqueado"
  }
  assert {
    condition     = cloudflare_zone_setting.min_tls_version.value == "1.2" && cloudflare_zone_setting.always_use_https.value == "on" && cloudflare_zone_setting.hsts.value.strict_transport_security.enabled
    error_message = "TLS 1.2, HTTPS sempre e HSTS"
  }
  assert {
    condition     = length(cloudflare_ruleset.response_headers[0].rules) == 1 && cloudflare_ruleset.response_headers[0].rules[0].expression == "http.host in {\"cdn.aedis.build\"}" && cloudflare_ruleset.response_headers[0].rules[0].action_parameters.headers["Content-Security-Policy"].value == "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    error_message = "a cdn leva os cabeçalhos de segurança padrão no ruleset único da fase, só no host dela"
  }
  assert {
    condition     = cloudflare_r2_custom_domain.cdn["cdn.aedis.build"].bucket_name == "aedis-cdn" && cloudflare_r2_custom_domain.cdn["cdn.aedis.build"].min_tls == "1.2" && cloudflare_r2_managed_domain.this["aedis-cdn"].enabled == false
    error_message = "domínio próprio do R2 com TLS 1.2 e dev URL desligado"
  }
  # O wildcard da Cloudflare (case-insensitive, * = zero ou mais caracteres, casa o valor inteiro) emulado em RE2 sobre
  # os padrões gerados: o domínio e os subdomínios passam, os parecidos não.
  assert {
    condition = alltrue([for referer in ["https://aedis.build/", "https://aedis.build/docs/x", "https://ui.aedis.build/", "https://a.b.aedis.build/p", "https://AEDIS.build/"] :
      anytrue([for p in flatten(regexall("wildcard \"([^\"]+)\"", cloudflare_ruleset.custom[0].rules[1].expression)) : can(regex("^(?i)${replace(replace(p, ".", "\\."), "*", ".*")}$", referer))])
    ])
    error_message = "Referer do domínio permitido ou de subdomínio dele precisa passar"
  }
  assert {
    condition = alltrue([for referer in ["https://evilaedis.build/", "https://aedis.build.evil.com/", "https://evil.com/", "http://aedis.build/", "https://aedis.builder/"] :
      !anytrue([for p in flatten(regexall("wildcard \"([^\"]+)\"", cloudflare_ruleset.custom[0].rules[1].expression)) : can(regex("^(?i)${replace(replace(p, ".", "\\."), "*", ".*")}$", referer))])
    ])
    error_message = "domínio parecido ou de outro site não passa"
  }
  assert {
    condition     = startswith(cloudflare_ruleset.custom[0].rules[1].expression, "http.host in {\"cdn.aedis.build\"} and http.referer ne \"\" and not (")
    error_message = "Referer vazio passa: a regra de hotlink só olha requisições com Referer"
  }
}

run "free_varios_workloads_com_forms_numa_regra_so" {
  command = plan

  variables {
    zone_name = "example.com"
    workloads = {
      site = { type = "site-ssr", hostnames = ["example.com", "www.example.com"], forms = ["/api/contato"], turnstile = true }
      app  = { type = "site-ssr", hostnames = ["app.example.com"], forms = ["/api/convites", "/api/login"], turnstile = true }
      api  = { type = "api", hostnames = ["api.example.com"] }
    }
    email_routing = {
      addresses = ["propostas@example.com"]
      rules     = [{ to = "contato@example.com", worker = "example-site" }]
    }
    r2_buckets = ["uploads"]
  }

  assert {
    condition     = length(cloudflare_ruleset.rate_limit[0].rules) == 1 && cloudflare_ruleset.rate_limit[0].rules[0].ref == "aedis_form_rate_limit"
    error_message = "no Free, os forms de todos os workloads cabem na única regra de rate limit da zona"
  }
  assert {
    condition     = cloudflare_ruleset.rate_limit[0].rules[0].expression == "http.request.method eq \"POST\" and ((http.host in {\"app.example.com\"} and http.request.uri.path in {\"/api/convites\" \"/api/login\"}) or (http.host in {\"example.com\" \"www.example.com\"} and http.request.uri.path in {\"/api/contato\"}))"
    error_message = "cada workload entra com os próprios hosts e rotas"
  }
  assert {
    condition     = cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.period == 10 && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.requests_per_period == 3 && cloudflare_ruleset.rate_limit[0].rules[0].action == "block" && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.mitigation_timeout == 10
    error_message = "3 POSTs por 10 s, bloqueio de 10 s no Free"
  }
  assert {
    condition     = cloudflare_email_routing_settings.this[0].support_subaddress == false
    error_message = "support_subaddress igual ao que o provider lê, sem update perpétuo"
  }
  assert {
    condition     = cloudflare_ruleset.custom[0].rules[0].expression == "(http.host in {\"app.example.com\" \"example.com\" \"www.example.com\"} and not http.request.method in {\"GET\" \"HEAD\" \"POST\"}) or (http.host in {\"api.example.com\"} and not http.request.method in {\"GET\" \"HEAD\" \"POST\" \"PUT\" \"PATCH\" \"DELETE\" \"OPTIONS\"})"
    error_message = "métodos por tipo numa regra só: api aceita mais verbos que site-ssr"
  }
  assert {
    condition     = cloudflare_turnstile_widget.this["app"].domains == tolist(["app.example.com"]) && cloudflare_turnstile_widget.this["site"].domains == tolist(["example.com", "www.example.com"]) && cloudflare_turnstile_widget.this["site"].mode == "managed"
    error_message = "um widget do Turnstile por workload, nos hostnames dele"
  }
  assert {
    condition     = cloudflare_email_routing_rule.this["contato@example.com"].actions[0].type == "worker" && length(cloudflare_email_routing_address.this) == 1
    error_message = "Email Routing da zona com o destino verificado e a regra para o Worker"
  }
  assert {
    condition     = length(cloudflare_r2_bucket.this) == 1 && cloudflare_r2_managed_domain.this["uploads"].enabled == false && length(cloudflare_r2_custom_domain.cdn) == 0
    error_message = "bucket da zona com o dev URL desligado e sem domínio próprio"
  }
  assert {
    condition     = length(cloudflare_ruleset.response_headers) == 0
    error_message = "sem cdn nem headers, a fase de cabeçalhos de resposta não é tocada"
  }
}

run "email_routing_com_destino_sensivel" {
  command = plan

  variables {
    zone_name = "example.com"
    workloads = {
      site = { type = "site-ssr", hostnames = ["example.com"], forms = ["/api/propostas"] }
    }
    email_routing = {
      addresses = [sensitive("propostas@example.com")]
      rules     = [{ to = sensitive("contato@example.com"), forward = [sensitive("propostas@example.com")] }]
    }
  }

  assert {
    condition     = length(cloudflare_email_routing_address.this) == 1 && length(cloudflare_email_routing_rule.this) == 1
    error_message = "um destino lido de variável sensível vira chave do for_each sem falhar o plan"
  }
}

run "pro" {
  command = plan

  variables {
    plan = "pro"
    workloads = {
      site = { type = "site-ssr", hostnames = ["aedis.build"], forms = ["/api/contato"] }
      cdn  = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "aedis-cdn", allowed_referers = ["aedis.build"] }
    }
  }

  assert {
    condition     = length(cloudflare_ruleset.managed) == 1 && [for r in cloudflare_ruleset.managed[0].rules : r.action_parameters.id] == ["efb7b8c949ac4650a09736fc376e9aee", "4814384a9e5d4991b9815dcfc25d2f1f"]
    error_message = "o pro executa o Cloudflare Managed e o OWASP"
  }
  assert {
    condition     = [for r in cloudflare_ruleset.rate_limit[0].rules : r.ref] == ["aedis_form_rate_limit", "aedis_site_rate_limit"] && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.period == 60 && cloudflare_ruleset.rate_limit[0].rules[1].expression == "http.host in {\"aedis.build\"} and not cf.client.bot"
    error_message = "o pro usa as duas regras: formulários (60 s) e limite geral sem a cdn"
  }
  assert {
    condition     = alltrue([for r in cloudflare_ruleset.rate_limit[0].rules : r.action == "managed_challenge" && r.ratelimit.mitigation_timeout == 0])
    error_message = "no pro o padrão é desafiar, com mitigation_timeout 0"
  }
  assert {
    condition     = cloudflare_bot_management.this.fight_mode == false && cloudflare_bot_management.this.sbfm_verified_bots == "allow"
    error_message = "no pro o Super Bot Fight Mode substitui o Bot Fight Mode e os bots verificados passam"
  }
}

run "regras_e_cabecalhos_restritos_ao_host_do_workload" {
  command = plan

  variables {
    workloads = {
      site = { type = "site-ssr", hostnames = ["aedis.build"], headers = { "X-Extra" = "1" } }
      api = {
        type      = "api"
        hostnames = ["api.aedis.build"]
        headers   = { "X-Origin-Verify" = "valor" }
        rules     = [{ description = "admin", expression = "starts_with(http.request.uri.path, \"/admin\")", action = "block", ref = "api_admin" }]
      }
    }
  }

  assert {
    condition     = cloudflare_ruleset.custom[0].rules[1].expression == "(http.host in {\"api.aedis.build\"}) and (starts_with(http.request.uri.path, \"/admin\"))" && cloudflare_ruleset.custom[0].rules[1].ref == "api_admin" && cloudflare_ruleset.custom[0].rules[1].description == "api: admin"
    error_message = "a regra do workload só vale nos hostnames dele"
  }
  assert {
    condition     = [for r in cloudflare_ruleset.response_headers[0].rules : r.expression] == ["http.host in {\"api.aedis.build\"}", "http.host in {\"aedis.build\"}"] && cloudflare_ruleset.response_headers[0].rules[0].action_parameters.headers["X-Origin-Verify"].value == "valor" && length(cloudflare_ruleset.response_headers[0].rules[0].action_parameters.headers) == 1
    error_message = "os cabeçalhos de cada workload ficam no host dele, sem os padrão da cdn"
  }
  assert {
    condition     = length(cloudflare_r2_bucket.this) == 0 && length(cloudflare_turnstile_widget.this) == 0
    error_message = "nada de R2 nem Turnstile sem pedido"
  }
}

run "cdn_sem_referer_permitido_e_dominio_fora_do_terraform" {
  command = plan

  variables {
    r2_buckets = ["aedis-cdn"]
    workloads = {
      cdn = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "aedis-cdn", headers = { "Referrer-Policy" = "same-origin" }, manage_domain = false }
    }
  }

  assert {
    condition     = cloudflare_ruleset.custom[0].rules[1].expression == "http.host in {\"cdn.aedis.build\"} and http.referer ne \"\""
    error_message = "sem allowed_referers, só Referer vazio passa"
  }
  assert {
    condition     = length(cloudflare_r2_custom_domain.cdn) == 0 && length(cloudflare_r2_bucket.this) == 1 && cloudflare_r2_managed_domain.this["aedis-cdn"].enabled == false
    error_message = "manage_domain = false tira só o domínio próprio; o bucket não duplica com r2_buckets e o dev URL fica desligado"
  }
  assert {
    condition     = cloudflare_ruleset.response_headers[0].rules[0].action_parameters.headers["Referrer-Policy"].value == "same-origin" && cloudflare_ruleset.response_headers[0].rules[0].action_parameters.headers["X-Content-Type-Options"].value == "nosniff"
    error_message = "headers da cdn sobrepõem ou somam aos padrão"
  }
  assert {
    condition     = length(cloudflare_ruleset.rate_limit) == 0
    error_message = "só cdn: nenhum site para o limite geral, nenhuma regra de rate limit"
  }
}

run "soma_dos_workloads_estoura_o_limite_do_free" {
  command = plan

  variables {
    workloads = {
      site = { type = "site-ssr", hostnames = ["aedis.build"], rules = [for i in range(2) : { description = "s${i}", expression = "http.request.uri.path eq \"/s${i}\"", action = "block" }] }
      cdn  = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "b", allowed_referers = ["aedis.build"] }
    }
    custom_rules = [{ description = "z", expression = "http.request.uri.path eq \"/z\"", action = "block" }]
  }

  # métodos 1 + site 2 + cdn 1 + zona 1 = 5: cabe.
  assert {
    condition     = length(cloudflare_ruleset.custom[0].rules) == 5
    error_message = "5 regras cabem no Free"
  }
}

run "uma_regra_a_mais_falha_no_plan" {
  command = plan

  variables {
    workloads = {
      site = { type = "site-ssr", hostnames = ["aedis.build"], rules = [for i in range(3) : { description = "s${i}", expression = "http.request.uri.path eq \"/s${i}\"", action = "block" }] }
      cdn  = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "b", allowed_referers = ["aedis.build"] }
    }
    custom_rules = [{ description = "z", expression = "http.request.uri.path eq \"/z\"", action = "block" }]
  }

  expect_failures = [cloudflare_ruleset.custom]
}

run "sem_workloads_nao_ha_regras" {
  command = plan

  variables {
    workloads = {}
  }

  assert {
    condition     = length(cloudflare_ruleset.custom) == 0 && length(cloudflare_ruleset.rate_limit) == 0 && length(cloudflare_ruleset.response_headers) == 0
    error_message = "sem workloads nem custom_rules, o módulo não toca as fases de regras"
  }
}

run "block_e_politicas_configuraveis" {
  command = plan

  variables {
    workloads         = { site = { type = "site-ssr", hostnames = ["aedis.build"], forms = ["/api/contato"] } }
    rate_limit_action = "block"
    bot_fight_mode    = false
    ai_bots           = { search = "allow", agent = "only_on_ad_pages", training = "allow", labyrinth = true }
  }

  assert {
    condition     = cloudflare_ruleset.rate_limit[0].rules[0].action == "block" && cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.mitigation_timeout == 10
    error_message = "com block, a ação dura um período (10 s no free)"
  }
  assert {
    condition     = cloudflare_bot_management.this.fight_mode == false && cloudflare_bot_management.this.ai_user == "only_on_ad_pages" && cloudflare_bot_management.this.ai_training == "disabled" && cloudflare_bot_management.this.crawler_protection == "enabled"
    error_message = "bot_fight_mode e ai_bots chegam ao bot_management"
  }
}

run "hostname_fora_da_zona" {
  command = plan

  variables {
    workloads = { site = { type = "site-static", hostnames = ["outro.example"] } }
  }

  expect_failures = [data.cloudflare_zone.this]
}

run "forms_em_site_estatico" {
  command = plan

  variables {
    workloads = { site = { type = "site-static", hostnames = ["aedis.build"], forms = ["/api/contato"] } }
  }

  expect_failures = [var.workloads]
}

run "hostname_em_dois_workloads" {
  command = plan

  variables {
    workloads = {
      a = { type = "site-static", hostnames = ["aedis.build"] }
      b = { type = "site-ssr", hostnames = ["aedis.build"] }
    }
  }

  expect_failures = [var.workloads]
}

run "cdn_sem_bucket" {
  command = plan

  variables {
    workloads = { cdn = { type = "cdn", hostnames = ["cdn.aedis.build"] } }
  }

  expect_failures = [var.workloads]
}

run "cdn_referer_com_esquema" {
  command = plan

  variables {
    workloads = { cdn = { type = "cdn", hostnames = ["cdn.aedis.build"], bucket = "b", allowed_referers = ["https://aedis.build"] } }
  }

  expect_failures = [var.workloads]
}

run "tipo_invalido" {
  command = plan

  variables {
    workloads = { x = { type = "worker", hostnames = ["aedis.build"] } }
  }

  expect_failures = [var.workloads]
}

run "plano_invalido" {
  command = plan

  variables {
    plan = "business"
  }

  expect_failures = [var.plan]
}

run "desafio_no_free_falha" {
  command = plan

  variables {
    rate_limit_action = "managed_challenge"
  }

  expect_failures = [cloudflare_ruleset.rate_limit]
}

run "acao_de_rate_limit_invalida" {
  command = plan

  variables {
    rate_limit_action = "js_challenge"
  }

  expect_failures = [var.rate_limit_action]
}

run "politica_de_ia_invalida" {
  command = plan

  variables {
    ai_bots = { training = "disallow" }
  }

  expect_failures = [var.ai_bots]
}

run "regra_de_email_com_worker_e_forward" {
  command = plan

  variables {
    email_routing = {
      addresses = []
      rules     = [{ to = "a@aedis.build", worker = "w", forward = ["b@example.com"] }]
    }
  }

  expect_failures = [var.email_routing]
}

# O exemplo de referência (examples/complete) planeja sem credenciais, com todas as variáveis e o limite do plano.
run "exemplo_complete" {
  command = plan

  module {
    source = "./examples/complete"
  }

  variables {
    origin_verify = "valor-de-teste"
  }

  assert {
    condition     = length(module.zone.zone_id) > 0
    error_message = "o exemplo completo planeja"
  }
}
