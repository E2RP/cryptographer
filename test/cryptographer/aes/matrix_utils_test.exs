defmodule Cryptographer.Aes.MatrixUtilsTest do
  use ExUnit.Case
  alias Cryptographer.Aes.MatrixUtils, as: Matrix

  describe "transpose/1" do
    test "returns a transposed square matrix" do
      matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
      assert Matrix.transpose(matrix) == [[1, 4, 7], [2, 5, 8], [3, 6, 9]]
    end

    test "returns a transposed matrix with more rows than columns" do
      matrix = [[1, 2], [4, 5], [7, 8]]
      assert Matrix.transpose(matrix) == [[1, 4, 7], [2, 5, 8]]
    end

    test "returns a transposed matrix with more columns than rows" do
      matrix = [[1, 2, 3, 4], [4, 5, 6, 7], [8, 9, 10, 11]]
      assert Matrix.transpose(matrix) == [[1, 4, 8], [2, 5, 9], [3, 6, 10], [4, 7, 11]]
    end
  end

  describe "multiply/2" do
  end
end
