--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2021, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module extractor
-- This module contains extractor access functions.
-- extractor is needed: https://github.com/michaelweiser/extractor
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local common = require "lua_scanners/common"

local N = 'extractor'

local static_boundary = rspamd_util.random_hex(32)

local function extractor_config(opts)

  local extractor_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    mime_parts_match_archive = false,
    url_check = '/v1/scan',
    url_report = '/v1/report',
    default_port = 8200,
    use_https = false,
    no_ssl_verify = true,
    use_gzip = false,
    timeout = 3.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 1d
    min_size = 300,
    message = '${SCANNER}: extractor threat message found: "${VIRUS}"',
    detection_category = "sandbox threat",
    default_score = 1,
    action = false,
    dynamic_scan = false,
    symbol = "EXTRACTOR",
    symbol_report = 'EXTRACTOR_REPORT',
    symbol_type = 'prefilter',
    symbol_report_type = 'postfilter',
    symbols = {
      extractor_good = {
        symbol = 'EXTRACTOR_GOOD';
        score = -1.0;
        description = "The extractor Whitelist entry";
      },
      extractor_pass = {
        symbol = 'EXTRACTOR_PASS';
        score = -1.0;
        description = "The extractor no threat detected";
      },
      extractor_in_process = {
        symbol = 'EXTRACTOR_IN_PROCESS';
        score = 0;
        description = "The extractor analysis was not finished";
      }
    },
    extractor_cache_name = N..'_jobs'
  }

  extractor_conf = lua_util.override_defaults(extractor_conf, opts)

  if not extractor_conf.prefix then
    extractor_conf.prefix = 'rs_' .. extractor_conf.name .. '_'
  end

  if not extractor_conf.log_prefix then
    if extractor_conf.name:lower() == extractor_conf.type:lower() then
      extractor_conf.log_prefix = extractor_conf.name
    else
      extractor_conf.log_prefix = extractor_conf.name .. ' (' .. extractor_conf.type .. ')'
    end
  end

  if not extractor_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  extractor_conf.upstreams = upstream_list.create(rspamd_config,
      extractor_conf.servers,
      extractor_conf.default_port)

  if extractor_conf.upstreams then
    lua_util.add_debug_alias('external_services', extractor_conf.name)
    return extractor_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      extractor_conf.servers)
  return nil
end

local function extractor_url(rule, addr, maybe_url)
  local url
  local port = addr:get_port()

  if port == 0 then
    port = rule.default_port
  end
  if rule.use_https then
    url = string.format('https://%s:%d%s', tostring(addr),
        port, maybe_url)
  else
    url = string.format('http://%s:%d%s', tostring(addr),
        port, maybe_url)
  end

  return url
end


local function extractor_check(task, content, digest, rule, maybe_part)
  local function extractor_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local log_prefix = rule.log_prefix..'_check'

    local request_url = extractor_url(rule, addr, rule.url_check)

    local form_data = {}
    --local form_data_length = 0
    local request_headers = {
      ['Content-Type'] = string.format('multipart/form-data; boundary="%s"', static_boundary)
    }

    local content_disposition = maybe_part:get_header('Content-Disposition')
    if content_disposition and string.sub(content_disposition,1,6) == 'inline' then
      request_headers['X-Content-Disposition'] = 'inline'
    end

    local mime_type, mime_subtype, mime_attr = maybe_part:get_type_full()

    local content_id = maybe_part:get_header('Content-ID')
    local detected_extension = maybe_part:get_detected_ext()

    table.insert(form_data, string.format('--%s\r\n', static_boundary))
    if mime_attr['name'] then
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n',
              mime_attr['name']))
    -- @TODO: use SHA256
    -- elseif content_id and detected_extension then
    --   table.insert(form_data,
    --       string.format('Content-Disposition: form-data; name="file"; filename="%s.%s"\r\n',
    --           content_id, detected_extension))
    elseif detected_extension then
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename="file.%s"\r\n',
              detected_extension))
    else
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename=""\r\n'))
    end

    if mime_type then
      table.insert(form_data,
          string.format('Content-Type: %s/%s\r\n', mime_type, mime_subtype))
    else
      table.insert(form_data, 'Content-Type: text/plain\r\n')
    end

    lua_util.debugm(N, task, '%s: form-data BODY : %s', log_prefix, form_data)

    table.insert(form_data, '\r\n')
    table.insert(form_data, content)
    table.insert(form_data, '\r\n')
    table.insert(form_data, string.format('--%s--\r\n', static_boundary))


    -- rspamd_http also adds Content-Length header
    -- for _, f in ipairs(form_data) do
    --   form_data_length = form_data_length + tonumber(#f)
    -- end
    -- request_headers['Content-Length'] = form_data_length

    lua_util.debugm(N, task, '%s: HTTP headers : %s', log_prefix, request_headers)

    local function extractor_callback(err_message, code, body, headers)

      local function extractor_requery(error)
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: error: %s; retry IP: %s; retries left: %s',
            log_prefix, error, addr, retransmits)

          request_url = extractor_url(rule, addr, rule.url_check)

          rspamd_http.request({
            task=task,
            url=request_url,
            timeout=rule.timeout,
            body=form_data,
            callback=extractor_callback,
            headers=request_headers,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed - err: %s', log_prefix, error)
          common.yield_result(task, rule,
              'failed to scan, maximum retransmits exceed - err: ' .. error,
              0.0, 'fail', maybe_part)
        end
      end

      if err_message or tonumber(code) >= 500 then

        extractor_requery(string.format('%s - %s', code, err_message))

      else
        -- Parse the response
        if upstream then upstream:ok() end

        local extractor_jobs_table = task:cache_get(rule.extractor_cache_name) or {}

        lua_util.debugm(N, task, '%s: return_debug: %s', log_prefix, tostring(body))

        local ucl_parser = ucl.parser()
        local ok, ucl_err = ucl_parser:parse_string(tostring(body))
        if not ok then
          rspamd_logger.errx(task, "%s: error parsing json response, retry: %s",
            log_prefix, ucl_err)
        end

        local result = ucl_parser:get_object()

        lua_util.debugm(N, task, '%s: Job ID: %s', log_prefix, result.job_id)
        extractor_jobs_table[digest] = result.job_id
        task:cache_set(rule.extractor_cache_name, extractor_jobs_table)

      end
    end

    rspamd_http.request({
      task=task,
      url=request_url,
      timeout=rule.timeout,
      body=form_data,
      callback=extractor_callback,
      headers=request_headers,
    })

  end

  if common.condition_check_and_continue(task, content, rule, digest,
      extractor_check_uncached, maybe_part) then
    return
  else
    extractor_check_uncached()
  end

end

local function extractor_report(task, content, digest, rule, maybe_part)

  local upstream = rule.upstreams:get_upstream_round_robin()
  local addr = upstream:get_addr()
  local retransmits = rule.retransmits
  local log_prefix = rule.log_prefix..'_report'

  local request_url = extractor_url(rule, addr, rule.url_report)

  local extractor_jobs_table = task:cache_get(rule.extractor_cache_name)

  if not extractor_jobs_table then return end

  local job_id = extractor_jobs_table[digest]

  --local filename = maybe_part:get_filename()
  --local extension = common.gen_extension(filename)

  local function extractor_callback(err_message, code, body, headers)

    local function extractor_requery(error)
      -- set current upstream to fail because an error occurred
      upstream:fail()

      -- retry with another upstream until retransmits exceeds
      if retransmits > 0 then

        retransmits = retransmits - 1

        -- Select a different upstream!
        upstream = rule.upstreams:get_upstream_round_robin()
        addr = upstream:get_addr()

        request_url = extractor_url(rule, addr, rule.url_report)

        lua_util.debugm(N, task, '%s error: %s; retry IP: %s; retries left: %s',
          log_prefix, error, addr, retransmits)

        rspamd_http.request({
          task=task,
          url=request_url..'/'..job_id,
          callback=extractor_callback,
          timeout = rule.timeout,
          mime_type='text/plain',
        })
      else
        rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed - err: %s', log_prefix, error)
        common.yield_result(task, rule,
            'failed to scan, maximum retransmits exceed - err: ' .. error,
            0.0, 'fail', maybe_part)
      end
    end

    if err_message or (code and tonumber(code) >= 500) then

      extractor_requery(code..' - '..err_message)

    elseif tonumber(code) == 404 then

      lua_util.debugm(N, task, '%s: got 404 - not finished for job: %s',
        log_prefix, job_id)
      common.yield_result(task, rule, string.format('job_id: %s', job_id),
        0.0, rule.symbols.extractor_in_process.symbol, maybe_part)
    else
      -- Parse the response
      if upstream then upstream:ok() end
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_string(tostring(body))
      if not ok then
        rspamd_logger.errx(task, "%s %s: error parsing json response, retry: %s",
          log_prefix, job_id, ucl_err)
      end

      local result = ucl_parser:get_object()

      lua_util.debugm(N, task, '%s: job-id %s - JSON OBJECT - %s', log_prefix, job_id, result)

      -- {[result] = bad, [reason] = Der Ausdruck (3) klassifizierte die Datei als Result.bad}

      if result.result and tostring(result.result) ~= '' then
        if tostring(result.result) == 'bad' then
          lua_util.debugm(N, task, '%s: job-id %s - found bad result - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            1.0, nil, maybe_part)
          common.save_cache(task, digest, rule, 
            string.format("job-id %s: %s", job_id, result.reason), 1.0, maybe_part)
        elseif tostring(result.result) == 'failed' or tostring(result.result) == 'unchecked' then
          lua_util.debugm(N, task, '%s: job-id %s - found failed/unchecked result - %s (%s)', 
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            1.0, 'fail', maybe_part)
        elseif tostring(result.result) == 'good' then
          lua_util.debugm(N, task, '%s: job-id %s - found good result - %s (%s)', 
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            rule.symbols.extractor_good.score, rule.symbols.extractor_good.symbol, maybe_part)
          -- Do not save negative report to cache for now
          -- common.save_cache(task, digest, rule,
          --   string.format("job-id %s: %s", job_id, result.reason), rule.symbols.extractor_good.score, maybe_part)
        elseif tostring(result.result) == 'ignored' then
          lua_util.debugm(N, task, '%s: job-id %s - found ignored result - %s (%s)', 
            log_prefix, job_id, result.result, result.reason)
          -- Do not save negative report to cache for now
          -- common.save_cache(task, digest, rule, 'OK', 0.0, maybe_part)
        elseif tostring(result.result) == 'unknown' then
          lua_util.debugm(N, task, '%s: job-id %s - found unknown result - %s (%s)', 
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            rule.symbols.extractor_pass.score, rule.symbols.extractor_pass.symbol, maybe_part)          
          -- Do not save negative report to cache for now
          -- common.save_cache(task, digest, rule, 'OK', 0.0, maybe_part)
        end
      else
        rspamd_logger.errx(task, "%s %s: REPORT no result found: %s (%s)",
          log_prefix, job_id, result.result, type(result.result))
      end
    end
  end

  if job_id and tostring(job_id) ~= "" then
      lua_util.debugm(N, task, '%s: Calling Job-ID : %s', log_prefix, job_id)
      rspamd_http.request({
        task=task,
        url=request_url..'/'..job_id,
        callback=extractor_callback,
        timeout = rule.timeout,
        mime_type='text/plain',
      })
  else
    rspamd_logger.infox(task, "%s: JOB-ID for part not in cache",
      log_prefix)
  end
end

return {
  type = {N, 'attachment scanner', 'hash', 'scanner'},
  description = 'extractor Threat Scanner',
  configure = extractor_config,
  check = extractor_check,
  report = extractor_report,
  name = N
}
