defmodule Cryptographer.Aes.Key do
  @type t :: <<_::128>>

  @spec generate() :: t()
  def generate(), do: 12 |> :crypto.strong_rand_bytes() |> Base.encode64()
end
