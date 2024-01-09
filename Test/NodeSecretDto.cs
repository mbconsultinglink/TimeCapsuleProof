using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TimeCapsuleProof
{
  public class NodeSecretDto
  {
    public required int NodeId { get; set; }
    public required List<NodeSecretMap> Keys { get; set; }
    public required List<NodeSecretMap> Ivs { get; set; }
    public required List<NodeSecretMap> Secret { get; set; }

    public override string ToString()
    {
      return $"NodeId: {NodeId} {Environment.NewLine}   Keys: {string.Join(" ",Keys)} {Environment.NewLine}" +
        $"   Ivs: {string.Join(" ", Ivs)} {Environment.NewLine}" +
        $"   Secret: {string.Join(" ", Secret)} {Environment.NewLine}";
    }
  }
  public class NodeSecretMap
  {
    public required byte[] Key { get; set; }
    public int Index { get; set; }
    public int Layer { get; set; }
    public override string ToString()
    {
      return $"(Layer: {Layer} Index:{Index} Key:{BitConverter.ToString(Key)})";
    }
  }
}
