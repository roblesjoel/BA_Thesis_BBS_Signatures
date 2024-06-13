For a detailed explanation read Readme.md

This is quick explanation on how to set up the code and how to run it.

After unpacking the zip or downloading it from the git run "npm install" in the root repository.
This installs all dependencies.

Then cd into the examples folder. 
There you have 4 files:
- createSignedBase: creates a signed VC based on the inputs in the input folder
- verifySignedBase: verifies the signed VC
- deriveDocument: creates selective disclosure VC based on the inputs in the input folder and the generated signed VC
- verifyDerivedDocument: verifies the selectively disclosed VC