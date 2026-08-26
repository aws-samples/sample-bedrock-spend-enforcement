-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
-- SPDX-License-Identifier: MIT-0
--
-- bedrock_cost_today — Athena view that prices every Bedrock invocation and
-- windows it to the current daily reset boundary (0400 UTC).
--
-- This file is a READ-ONLY REFERENCE COPY for review and customization.
-- CloudFormation cannot include an external .sql file inline, so the version
-- that actually gets deployed lives embedded in infra/athena.yaml's
-- ViewManagerFunction (a custom-resource Lambda that runs this exact SQL via
-- CREATE OR REPLACE VIEW on every stack create/update). If you edit the
-- pricing table, the model classification, or the reset window, make the
-- same change in BOTH places — this file, and the CREATE_VIEW_SQL string in
-- infra/athena.yaml — and bump that template's ViewVersion property so
-- CloudFormation knows to re-run the DDL.
--
-- PREREQUISITES
--   infra/athena.yaml deploys the Glue source table (bedrocklogs_metadata_clean)
--   this view reads from. Bedrock model invocation logging must be enabled,
--   delivering JSON to the S3 bucket you pass as the LogsBucket parameter.
--
-- CUSTOMIZE
--   1. Model classification (the first CASE) and per-token pricing (the second
--      CASE) — add a branch for any model not already listed, and verify rates
--      against https://aws.amazon.com/bedrock/pricing/ for your Region. An
--      unmapped model intentionally falls back to the highest-priced tier
--      rather than $0, so it can never bypass enforcement — but you'll want
--      to add its real rate promptly once you see it appear as 'Unknown'.
--   2. The geo-surcharge multiplier (1.1x) applies to newer cross-region
--      inference-profile models — adjust the model list if AWS changes which
--      models route through geo-priced inference profiles.
--   3. The reset boundary (INTERVAL '4' HOUR, i.e. 0400 UTC) — change both
--      occurrences in the `bounds` CTE to shift the daily reset hour.
--   4. The human/service classification regex — matches a firstname.lastname
--      SSO username convention; adjust if yours differs.
--
-- USAGE
--   The enforcement Lambda (lambda/handler.py) queries this view once per run:
--     SELECT person, model, raw_model, usage_type, ...
--     FROM bedrock_cost_today
--     GROUP BY person, model, raw_model, usage_type, ...
--   grouping and summing estimated_cost per person in application code, so
--   the scan happens once per run regardless of how many downstream
--   consumers need the numbers.

CREATE OR REPLACE VIEW default.bedrock_cost_today AS
WITH
  bounds AS (
    SELECT
      (date_trunc('day', (current_timestamp AT TIME ZONE 'UTC' - INTERVAL '4' HOUR)) + INTERVAL '4' HOUR)  AS window_start,
      (date_trunc('day', (current_timestamp AT TIME ZONE 'UTC' - INTERVAL '4' HOUR)) + INTERVAL '28' HOUR) AS window_end
  ),
  raw_logs AS (
    SELECT datehour, identity, modelId, operation, input, output
    FROM default.bedrocklogs_metadata_clean CROSS JOIN bounds
    WHERE operation IN ('InvokeModel','InvokeModelWithResponseStream','Converse','ConverseStream')
      AND datehour >= date_format(window_start, '%Y/%m/%d/%H')
      AND datehour <  date_format(window_end,   '%Y/%m/%d/%H')
  ),
  raw AS (
    SELECT
      CAST(DATE_TRUNC('day', DATE_PARSE(datehour, '%Y/%m/%d/%H')) AS DATE) AS day,
      datehour,
      identity.arn AS arn,
      REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '') AS person,
      modelId AS raw_model, operation,
      CASE
        WHEN modelId LIKE '%fable-5%' OR modelId LIKE '%fable5%' THEN 'Fable 5'
        WHEN modelId LIKE '%opus-5%'            THEN 'Opus 5'
        WHEN modelId LIKE '%sonnet-5%'          THEN 'Sonnet 5'
        WHEN modelId LIKE '%opus-4-8%'          THEN 'Opus 4.8'
        WHEN modelId LIKE '%opus-4-7%'          THEN 'Opus 4.7'
        WHEN modelId LIKE '%opus-4-6%'          THEN 'Opus 4.6'
        WHEN modelId LIKE '%opus-4-5%'          THEN 'Opus 4.5'
        WHEN modelId LIKE '%opus-4-1%'          THEN 'Opus 4.1'
        WHEN modelId LIKE '%opus-4-20250514%'   THEN 'Opus 4'
        WHEN modelId LIKE '%sonnet-4-6%'        THEN 'Sonnet 4.6'
        WHEN modelId LIKE '%sonnet-4-5-20250929%' THEN 'Sonnet 4.5'
        WHEN modelId LIKE '%sonnet-4-20250514%' THEN 'Sonnet 4'
        WHEN modelId LIKE '%haiku-4-5%'         THEN 'Haiku 4.5'
        WHEN modelId LIKE '%3-7-sonnet%' OR modelId LIKE '%claude-3.7-sonnet%' THEN 'Sonnet 3.7'
        WHEN modelId LIKE '%3-5-sonnet%' OR modelId LIKE '%sonnet-3-5%' OR modelId LIKE '%sonnet-v2%' THEN 'Sonnet 3.5'
        WHEN modelId LIKE '%3-5-haiku%'  OR modelId LIKE '%3.5-haiku%'  OR modelId LIKE '%haiku-20241022%' THEN 'Haiku 3.5'
        WHEN modelId LIKE '%3-sonnet-20240229%' OR modelId LIKE '%sonnet-20240229%' THEN 'Sonnet 3'
        WHEN modelId LIKE '%3-opus-20240229%'   OR modelId LIKE '%opus-20240229%'   THEN 'Opus 3'
        WHEN modelId LIKE '%3-haiku-20240307%'  OR modelId LIKE '%haiku-20240307%'  THEN 'Haiku 3'
        WHEN modelId LIKE '%titan-embed-text-v2%' THEN 'Titan Embed v2'
        WHEN modelId LIKE '%titan-embed%'       THEN 'Titan Embed'
        WHEN modelId LIKE '%llama-3-3-70b%'     THEN 'Llama 3.3 70B'
        WHEN modelId LIKE '%llama-3-2-3b%'      THEN 'Llama 3.2 3B'
        WHEN modelId LIKE '%llama-3-2-1b%'      THEN 'Llama 3.2 1B'
        WHEN modelId LIKE '%llama-3-1-70b%'     THEN 'Llama 3.1 70B'
        WHEN modelId LIKE '%llama-3-1-8b%'      THEN 'Llama 3.1 8B'
        WHEN modelId LIKE '%nova-2-lite%'       THEN 'Nova 2 Lite'
        WHEN modelId LIKE '%nova-pro%'          THEN 'Nova Pro'
        WHEN modelId LIKE '%nova-lite%'         THEN 'Nova Lite'
        WHEN modelId LIKE '%nova-micro%'        THEN 'Nova Micro'
        WHEN modelId LIKE '%cohere%'            THEN 'Cohere'
        WHEN modelId LIKE '%deepseek%'          THEN 'DeepSeek'
        ELSE 'Unknown'
      END AS model,
      COALESCE(input.inputTokenCount,           0) AS uncached_input_tokens,
      COALESCE(input.cacheReadInputTokenCount,  0) AS cache_read_tokens,
      COALESCE(input.cacheWriteInputTokenCount, 0) AS cache_write_tokens,
      COALESCE(output.outputTokenCount,         0) AS output_tokens,
      CASE WHEN modelId LIKE '%/global.%' OR modelId LIKE 'global.%' THEN 'global' ELSE 'geo' END AS endpoint_type,
      CASE
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%service%'    THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%lambda%'     THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%bot%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%automation%' THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%system%'     THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%app%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%api%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%pipeline%'   THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%deploy%'     THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%build%'      THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%ci-%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%cd-%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%worker%'     THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%job%'        THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%scheduled%'  THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE '%cron%'       THEN 'non-human'
        WHEN LOWER(REPLACE(REGEXP_EXTRACT(identity.arn, '/([^/]+)$'), '/', '')) LIKE 'claude-xtm-%' THEN 'non-human'
        ELSE 'human'
      END AS usage_type
    FROM raw_logs
  )
SELECT
  day, arn, person, raw_model, model, operation,
  endpoint_type, usage_type,
  uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens,
  (uncached_input_tokens + cache_read_tokens + cache_write_tokens) AS total_input_tokens,
  (
    CASE model
      WHEN 'Fable 5'        THEN ((uncached_input_tokens*1E1)+(output_tokens*5E1)+(cache_write_tokens*1.25E1)+(cache_read_tokens*1E0))
      WHEN 'Opus 5'         THEN ((uncached_input_tokens*5E0)+(output_tokens*2.5E1)+(cache_write_tokens*6.25E0)+(cache_read_tokens*5E-1))
      WHEN 'Sonnet 5'       THEN ((uncached_input_tokens*2E0)+(output_tokens*1E1)+(cache_write_tokens*2.5E0)+(cache_read_tokens*2E-1))
      WHEN 'Opus 4.8'       THEN ((uncached_input_tokens*5E0)+(output_tokens*2.5E1)+(cache_write_tokens*6.25E0)+(cache_read_tokens*5E-1))
      WHEN 'Opus 4.7'       THEN ((uncached_input_tokens*5E0)+(output_tokens*2.5E1)+(cache_write_tokens*6.25E0)+(cache_read_tokens*5E-1))
      WHEN 'Opus 4.6'       THEN ((uncached_input_tokens*5E0)+(output_tokens*2.5E1)+(cache_write_tokens*6.25E0)+(cache_read_tokens*5E-1))
      WHEN 'Opus 4.5'       THEN ((uncached_input_tokens*5E0)+(output_tokens*2.5E1)+(cache_write_tokens*6.25E0)+(cache_read_tokens*5E-1))
      WHEN 'Opus 4.1'       THEN ((uncached_input_tokens*1.5E1)+(output_tokens*7.5E1)+(cache_write_tokens*1.875E1)+(cache_read_tokens*1.5E0))
      WHEN 'Opus 4'         THEN ((uncached_input_tokens*1.5E1)+(output_tokens*7.5E1)+(cache_write_tokens*1.875E1)+(cache_read_tokens*1.5E0))
      WHEN 'Opus 3'         THEN ((uncached_input_tokens*1.5E1)+(output_tokens*7.5E1)+(cache_write_tokens*1.875E1)+(cache_read_tokens*1.5E0))
      WHEN 'Sonnet 4.6'     THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Sonnet 4.5'     THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Sonnet 4'       THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Sonnet 3.7'     THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Sonnet 3.5'     THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Sonnet 3'       THEN ((uncached_input_tokens*3E0)+(output_tokens*1.5E1)+(cache_write_tokens*3.75E0)+(cache_read_tokens*3E-1))
      WHEN 'Haiku 4.5'      THEN ((uncached_input_tokens*1E0)+(output_tokens*5E0)+(cache_write_tokens*1.25E0)+(cache_read_tokens*1E-1))
      WHEN 'Haiku 3.5'      THEN ((uncached_input_tokens*8E-1)+(output_tokens*4E0)+(cache_write_tokens*1E0)+(cache_read_tokens*8E-2))
      WHEN 'Haiku 3'        THEN ((uncached_input_tokens*2.5E-1)+(output_tokens*1.25E0)+(cache_write_tokens*3E-1)+(cache_read_tokens*3E-2))
      WHEN 'Titan Embed v2' THEN (uncached_input_tokens*2E-2)
      WHEN 'Titan Embed'    THEN (uncached_input_tokens*2E-2)
      WHEN 'Llama 3.3 70B'  THEN ((uncached_input_tokens*7.2E-1)+(output_tokens*7.2E-1))
      WHEN 'Llama 3.2 3B'   THEN ((uncached_input_tokens*1.5E-1)+(output_tokens*1.5E-1))
      WHEN 'Llama 3.2 1B'   THEN ((uncached_input_tokens*1E-1)+(output_tokens*1E-1))
      WHEN 'Llama 3.1 70B'  THEN ((uncached_input_tokens*7.2E-1)+(output_tokens*7.2E-1))
      WHEN 'Llama 3.1 8B'   THEN ((uncached_input_tokens*2.2E-1)+(output_tokens*2.2E-1))
      WHEN 'Nova 2 Lite'    THEN ((uncached_input_tokens*3E-1)+(output_tokens*2.5E0))
      WHEN 'Nova Pro'       THEN ((uncached_input_tokens*8E-1)+(output_tokens*3.2E0))
      WHEN 'Nova Lite'      THEN ((uncached_input_tokens*6E-2)+(output_tokens*2.4E-1))
      WHEN 'Nova Micro'     THEN ((uncached_input_tokens*3.5E-2)+(output_tokens*1.4E-1))
      -- Unpriced/unmapped model: fall back to the highest-priced tier
      -- (Opus 4-generation rate) rather than $0. Enforcement must fail
      -- safe — a $0 estimate lets an unmapped model bypass spend limits
      -- entirely. handler.py alerts (UnmappedModelSpend metric) whenever
      -- it sees model='Unknown' rows so the real rate gets added promptly.
      ELSE ((uncached_input_tokens*1.5E1)+(output_tokens*7.5E1)+(cache_write_tokens*1.875E1)+(cache_read_tokens*1.5E0))
    END / 1E6
  ) * CASE
    -- 1.1x geo surcharge applies only to newer cross-region inference
    -- profile models (Opus 4.5+, Sonnet 4.5+, Haiku 4.5, Fable 5, Sonnet 5, Opus 5,
    -- Nova 2 Lite). Older generations (Opus 4.1 and below, Sonnet 4 and below, Nova
    -- Lite/Pro/Micro v1, etc.) are not routed through geo-priced inference profiles
    -- in this account.
    WHEN endpoint_type = 'geo'
      AND model IN ('Opus 4.5','Opus 4.6','Opus 4.7','Opus 4.8','Opus 5','Fable 5','Sonnet 4.5','Sonnet 4.6','Sonnet 5','Haiku 4.5','Nova 2 Lite')
    THEN 1.1E0
    ELSE 1E0
  END AS estimated_cost
FROM raw;
