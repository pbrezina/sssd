extern struct dp_option default_krb5_opts[];

static int kcm_get_auth_provider_options(struct kcm_ctx *kctx,
                                         struct krb5_ctx *krb5_ctx)
{
    errno_t ret;
    char *lifetime_str;
    char *rtime;
    bool validate;
    bool canonicalize;
    int child_timeout;
    struct dp_option *opts;
    const char *conf_path;
    char *auth_provider;
    struct sss_domain_info *domains;
    struct sss_domain_info *dom;

    ret = confdb_get_domains(kctx->rctx->cdb, &domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get domains\n");
        goto done;
    }

    for (dom = domains; dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {

        conf_path = talloc_asprintf(kctx->rctx, CONFDB_DOMAIN_PATH_TMPL,
                                    dom->name);
        if (conf_path == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
            ret = ENOMEM;
            goto done;
        }

        ret = confdb_get_string(kctx->rctx->cdb,
                                kctx->rctx,
                                conf_path,
                                CONFDB_DOMAIN_AUTH_PROVIDER,
                                NULL, &auth_provider);

        if (auth_provider == NULL ||
            strcasecmp(auth_provider, "krb5") != 0) {
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Checking auth provider options for: "
                                 "[%s]\n", dom->name);
        ret = dp_get_options(kctx->rctx, kctx->rctx->cdb, conf_path,
                             default_krb5_opts, KRB5_OPTS, &opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options failed\n");
            goto done;
        }

        /* Lifetime */
        lifetime_str = dp_opt_get_string(opts, KRB5_LIFETIME);
        if (lifetime_str != NULL) {
            ret = krb5_string_to_deltat(lifetime_str,
                                        &krb5_ctx->lifetime);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to convert lifetime string.\n");
                goto done;
            }
            krb5_ctx->lifetime_str = lifetime_str;
        }

        /* Renewable lifetime */
        rtime = dp_opt_get_string(opts, KRB5_RENEWABLE_LIFETIME);
        if (rtime != 0) {
            ret = krb5_string_to_deltat(rtime, &krb5_ctx->rlife);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to convert renewable lifetime string.\n");
                goto done;
            }
            krb5_ctx->rlife_str = rtime;
        }

        /* Validate */
        validate = dp_opt_get_bool(opts, KRB5_VALIDATE);
        ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_VALIDATE, validate);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot set dp opt krb5 validate\n");
            goto done;
        }

        /* Canonicalize */
        canonicalize = dp_opt_get_bool(opts, KRB5_CANONICALIZE);
        ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_CANONICALIZE,
                              canonicalize);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 "
                                     "canonicalize\n");
            goto done;
        }

        /* Child timeout */
        child_timeout = dp_opt_get_int(opts, KRB5_AUTH_TIMEOUT);
        if (child_timeout > 0) {
            ret = dp_opt_set_int(krb5_ctx->opts, KRB5_AUTH_TIMEOUT,
                                 child_timeout);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child "
                                         "timeout\n");
                goto done;
            }
        }

        break;
    }

    ret = EOK;
done:
    return ret;
}

static int kcm_get_krb5_config(struct kcm_ctx *kctx,
                               struct krb5_ctx *krb5_ctx)
{
    errno_t ret;
    char *rtime;
    char *lifetime_str;
    bool validate;
    bool canonicalize;
    int child_timeout;
    bool kcm_renew_option_defined;

    /* Lifetime */
    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_KRB5_LIFETIME,
                            NULL, &lifetime_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb lifetime\n");
        goto done;
    }

    if (lifetime_str != NULL) {
        ret = krb5_string_to_deltat(lifetime_str, &krb5_ctx->lifetime);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert lifetime string.\n");
            goto done;
        }
        kcm_renew_option_defined = true;
        krb5_ctx->lifetime_str = lifetime_str;
    }

    /* Renewable lifetime */
    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_KRB5_RENEWABLE_LIFETIME,
                            NULL, &rtime);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb renewable lifetime\n");
        goto done;
    }

    if (rtime != 0) {
        ret = krb5_string_to_deltat(rtime, &krb5_ctx->rlife);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert renewable lifetime "
                                     "string.\n");
            goto done;
        }
        kcm_renew_option_defined = true;
        krb5_ctx->rlife_str = rtime;
    }

    /* Validate */
    ret = confdb_get_bool(kctx->rctx->cdb,
                          kctx->rctx->confdb_service_path,
                          CONFDB_KCM_KRB5_VALIDATE,
                          false, &validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb krb5 validate\n");
        goto done;
    }

    ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_VALIDATE, validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 validate\n");
        goto done;
    }

    /* Canonicalize */
    ret = confdb_get_bool(kctx->rctx->cdb,
                          kctx->rctx->confdb_service_path,
                          CONFDB_KCM_KRB5_CANONICALIZE,
                          false, &canonicalize);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb krb5 canonicalize\n");
        goto done;
    }
    ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_CANONICALIZE, canonicalize);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 canonicalize\n");
        goto done;
    }

    /* Child timeout */
    ret = confdb_get_int(kctx->rctx->cdb,
                         kctx->rctx->confdb_service_path,
                         CONFDB_KCM_KRB5_AUTH_TIMEOUT,
                         0, &child_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get krb5 child timeout\n");
        goto done;
    }

    if (child_timeout > 0) {
        ret = dp_opt_set_int(krb5_ctx->opts, KRB5_AUTH_TIMEOUT, child_timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child timeout\n");
            goto done;
        }
        kcm_renew_option_defined = true;
    }

    /* Fallback to first auth_provider=krb5 domain */
    if (kcm_renew_option_defined == false) {
        ret = kcm_get_auth_provider_options(kctx, krb5_ctx);
        if (ret != EOK) {
            /* Not fatal */
            DEBUG(SSSDBG_OP_FAILURE, "Failed to read auth provider options\n");
        }
    }

    ret = EOK;
done:
    return ret;
}

int kcm_get_renewal_config(struct kcm_ctx *kctx,
                           struct krb5_ctx **_krb5_ctx)
{
    int ret;
    struct krb5_ctx *krb5_ctx;
    int i;

    krb5_ctx = talloc_zero(kctx->rctx, struct krb5_ctx);
    if (krb5_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error allocating krb5_ctx\n");
        ret = ENOMEM;
        goto done;
    }

    /* Set default Kerberos options */
    krb5_ctx->opts = talloc_zero_array(krb5_ctx, struct dp_option, KRB5_OPTS);
    if (!krb5_ctx->opts) goto done;
    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
        switch (krb5_ctx->opts[i].type) {
            case DP_OPT_STRING:
                ret = dp_opt_set_string(krb5_ctx->opts, i,
                                        default_krb5_opts[i].def_val.string);
                break;
            case DP_OPT_BLOB:
                ret = dp_opt_set_blob(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.blob);
                break;
            case DP_OPT_NUMBER:
                ret = dp_opt_set_int(krb5_ctx->opts, i,
                                     default_krb5_opts[i].def_val.number);
                break;
            case DP_OPT_BOOL:
                ret = dp_opt_set_bool(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.boolean);
                break;
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed setting default KCM kerberos "
                                     "options\n");
            talloc_free(krb5_ctx->opts);
            goto done;
        }
    }

    /* Override with config options */
    kcm_get_krb5_config(kctx, krb5_ctx);

    *_krb5_ctx = krb5_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(krb5_ctx);
    }
    return ret;
}


