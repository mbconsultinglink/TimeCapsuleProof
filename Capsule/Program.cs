using TimeCapsuleProof;

var nodes = GenerateTimeCapsule.Generate("This is my time capsule", "123-41234-123456789");
GenerateTimeCapsule.DiscoverSecret(nodes);
Console.WriteLine("Done!");
Console.ReadLine();


