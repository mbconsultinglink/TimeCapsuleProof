using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TimeCapsuleProof
{
  public static class GenerateTimeCapsule
  {
    public static List<NodeSecretDto> Generate(string secret, string publicId)
    {
      var keyLength = 32;
      var ivLength = 16;
      var numberOfNodes = 7d;
      var keyBytesPerNode = (int)Math.Ceiling(keyLength / numberOfNodes);
      var ivBytesPerNode = (int)Math.Ceiling(ivLength / numberOfNodes);
      var nodes = new List<NodeSecretDto>();

      var key1 = RandomNumberGenerator.GetBytes(keyLength);
      var key2 = RandomNumberGenerator.GetBytes(keyLength);
      var key3 = RandomNumberGenerator.GetBytes(keyLength);

      var iv1 = RandomNumberGenerator.GetBytes(ivLength);
      var iv2 = RandomNumberGenerator.GetBytes(ivLength);
      var iv3 = RandomNumberGenerator.GetBytes(ivLength);

      var secretBytes = Encoding.UTF8.GetBytes(
        JsonSerializer.Serialize(new { Secret = secret, SecretPublicId = publicId }));
      var secret1Encripted = AesEncryption.Encrypt(secretBytes, key1, iv1);
      var secret2Encripted = AesEncryption.Encrypt(secret1Encripted, key2, iv2);
      var secret3Encripted = AesEncryption.Encrypt(secret2Encripted, key3, iv3);

      for (int i = 0; i < numberOfNodes; i++)
        nodes.Add(new NodeSecretDto
        {
          NodeId = i,
          Keys = [],
          Ivs = [],
          Secret = []
        });

      var nodeIndex = 0;
      var listOfKeys = new List<byte[]> { key1, key2, key3 };
      var layer = 0;
      foreach (var keyToShare in listOfKeys)
      {
        nodes = [.. nodes.OrderBy(a => Guid.NewGuid())]; //Shuffle 
        nodeIndex = 0;
        for (int i = 0; i < keyLength; i += keyBytesPerNode)
        {
          nodes[nodeIndex++].Keys.Add(new NodeSecretMap
          {
            Key = keyToShare.Skip(i).
            Take(i + keyBytesPerNode < keyLength ? keyBytesPerNode : keyLength - i).ToArray(),
            Index = nodeIndex - 1,
            Layer = layer
          });
        }
        layer++;
      }

      var listOfIvs = new List<byte[]> { iv1, iv2, iv3 };
      layer = 0;
      foreach (var ivToShare in listOfIvs)
      {
        nodes = [.. nodes.OrderBy(a => Guid.NewGuid())]; //Shuffle 
        nodeIndex = 0;
        for (int i = 0; i < ivLength; i += ivBytesPerNode)
        {
          nodes[nodeIndex++].Ivs.Add(new NodeSecretMap
          {
            Key = ivToShare.Skip(i).
            Take(i + ivBytesPerNode < ivLength ? ivBytesPerNode : ivLength - i).ToArray(),
            Index = nodeIndex - 1,
            Layer = layer
          });
        }
        layer++;
      }
      nodes = [.. nodes.OrderBy(a => Guid.NewGuid())]; //Shuffle 

      var secretPerNode = (int)Math.Ceiling(secret3Encripted.Length / numberOfNodes);
      nodeIndex = 0;
      for (int i = 0; i < secret3Encripted.Length; i += secretPerNode)
      {
        nodes[nodeIndex++].Secret.Add(new NodeSecretMap
        {
          Key = secret3Encripted.Skip(i).
          Take(i + secretPerNode < secret3Encripted.Length ? secretPerNode : secret3Encripted.Length - i).ToArray(),
          Index = nodeIndex - 1
        });

      }
      foreach (var node in nodes.OrderBy(x => x.NodeId))
        Console.WriteLine(node);

      return nodes;
    }

    public static void DiscoverSecret(List<NodeSecretDto> nodes)
    {
      var key1Decompose = nodes.SelectMany(x => x.Keys).Where(x => x.Layer == 0).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();
      var key2Decompose = nodes.SelectMany(x => x.Keys).Where(x => x.Layer == 1).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();
      var key3Decompose = nodes.SelectMany(x => x.Keys).Where(x => x.Layer == 2).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();


      var iv1Decompose = nodes.SelectMany(x => x.Ivs).Where(x => x.Layer == 0).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();
      var iv2Decompose = nodes.SelectMany(x => x.Ivs).Where(x => x.Layer == 1).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();
      var iv3Decompose = nodes.SelectMany(x => x.Ivs).Where(x => x.Layer == 2).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();

      var secret3Decripted = nodes.SelectMany(x => x.Secret).
        OrderBy(x => x.Index).SelectMany(x => x.Key).ToArray();

      var secret2Decripted = AesEncryption.Decrypt(secret3Decripted, key3Decompose, iv3Decompose);
      var secret1Decripted = AesEncryption.Decrypt(secret2Decripted, key2Decompose, iv2Decompose);
      var secret0Decripted = AesEncryption.Decrypt(secret1Decripted, key1Decompose, iv1Decompose);

      Console.WriteLine($"Secret decripted:{Encoding.UTF8.GetString(secret0Decripted)}");
    }
  }
}
