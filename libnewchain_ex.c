#include "erl_nif.h"
#include "libnewchain.h"
#include "trezor/ecdsa.h"
#include "trezor/nist256p1.h"

static ERL_NIF_TERM error_result(ErlNifEnv *env, char *error_msg)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, error_msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM ok_result(ErlNifEnv *env, ERL_NIF_TERM *r)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), *r);
}

int get_recid(ErlNifEnv *env, ERL_NIF_TERM argv, int *recid)
{

    if (!enif_get_int(env, argv, recid))
    {
        return 0;
    }

    if (*recid >= 0 && *recid <= 3)
    {
        return 1;
    }

    return 0;
}

static ERL_NIF_TERM
newchain_recover_public_key_ex(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM r;
    ErlNifBinary message_hash, signature;
    int result;
    size_t pubkeylen = 65;
    int recid = 0;
    unsigned char *finished_recpubkey_buf;

    if (!enif_inspect_binary(env, argv[0], &message_hash))
    {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[1], &signature))
    {
        return enif_make_badarg(env);
    }

    if (!get_recid(env, argv[2], &recid))
    {
        return error_result(env, "Recovery id invalid 0-3");
    }

    finished_recpubkey_buf = enif_make_new_binary(env, pubkeylen, &r);
    // Now do ECDSA recovery
    // result = newchain_recover_public_key(message_hash.data, signature.data, recid, finished_recpubkey_buf);
    result = ecdsa_recover_pub_from_sig(&nist256p1, finished_recpubkey_buf, signature.data, message_hash.data, recid);

    if (result != 0)
    {
        return error_result(env, "ecdsa recovery problem");
    }

    return ok_result(env, &r);
}

// Let's define the array of ErlNifFunc beforehand:
static ErlNifFunc nif_funcs[] = {
    // {erl_function_name, erl_function_arity, c_function}
    {"newchain_recover_public_key_ex", 3, newchain_recover_public_key_ex}};

ERL_NIF_INIT(Elixir.LibNewChain, nif_funcs, NULL, NULL, NULL, NULL)

