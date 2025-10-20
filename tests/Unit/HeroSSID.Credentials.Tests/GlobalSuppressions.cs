// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
using System.Diagnostics.CodeAnalysis;

// Test projects: Allow underscores in test method names (Arrange_Act_Assert pattern)
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Test method naming convention", Scope = "namespaceanddescendants", Target = "~N:HeroSSID.Credentials.Tests")]

// Test projects: ConfigureAwait not needed in test code
[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "Not needed in test code", Scope = "namespaceanddescendants", Target = "~N:HeroSSID.Credentials.Tests")]
