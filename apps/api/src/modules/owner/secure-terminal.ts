export function readSecretNoEcho(input: NodeJS.ReadStream, output: NodeJS.WriteStream, prompt: string): Promise<string> {
  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== "function") {
    return Promise.reject(new Error("Secret input requires a no-echo interactive terminal"));
  }
  output.write(prompt);
  input.setRawMode(true);
  input.resume();
  return new Promise((resolveSecret,rejectSecret)=>{
    const characters:string[]=[];
    const finish=(error?:Error)=>{
      input.off("data",onData);
      input.setRawMode(false);
      output.write("\n");
      if(error)rejectSecret(error);else resolveSecret(characters.join(""));
    };
    const onData=(chunk:Buffer)=>{
      for(const character of chunk.toString("utf8")){
        if(character==="\u0003")return finish(new Error("Secret input cancelled"));
        if(character==="\r"||character==="\n")return finish();
        if(character==="\u007f"||character==="\b")characters.pop();
        else if(character>=" "&&character<="~")characters.push(character);
      }
    };
    input.on("data",onData);
  });
}
