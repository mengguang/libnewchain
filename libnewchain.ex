# libnewchain.ex
defmodule LibNewChain do
  @on_load :load_nifs

  def load_nifs do
    :erlang.load_nif('./libnewchain_ex', 0)
  end

  def newchain_recover_public_key_ex(_message_hash,_signature,_v) do
    raise "NIF newchain_recover_public_key_ex/3 not implemented"
  end
end

