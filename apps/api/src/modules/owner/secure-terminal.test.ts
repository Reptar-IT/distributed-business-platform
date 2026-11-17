import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { readSecretNoEcho } from "./secure-terminal.js";

class FakeTerminalInput extends EventEmitter {
  isTTY=true;
  rawModes:boolean[]=[];
  rawMode=false;
  setRawMode(value:boolean){this.rawMode=value;this.rawModes.push(value);return this;}
  resume(){return this;}
}

function fakeOutput(){
  const writes:string[]=[];
  return {stream:{isTTY:true,write:(value:string)=>{writes.push(value);return true;}} as unknown as NodeJS.WriteStream,writes};
}

describe("no-echo credential input",()=>{
  it("collects ASCII secret input while terminal echo is disabled and restores terminal mode",async()=>{
    const input=new FakeTerminalInput() as unknown as NodeJS.ReadStream & FakeTerminalInput;
    const output=fakeOutput();
    const pending=readSecretNoEcho(input,output.stream,"Credential: ");
    input.emit("data",Buffer.from("secret-part"));
    input.emit("data",Buffer.from("-tail\r"));
    await expect(pending).resolves.toBe("secret-part-tail");
    expect(input.rawModes).toEqual([true,false]);
    expect(output.writes.join("")).toBe("Credential: \n");
    expect(output.writes.join("")).not.toContain("secret-part");
  });

  it("does not echo a cancelled secret and restores terminal mode",async()=>{
    const input=new FakeTerminalInput() as unknown as NodeJS.ReadStream & FakeTerminalInput;
    const output=fakeOutput();
    const pending=readSecretNoEcho(input,output.stream,"Credential: ");
    input.emit("data",Buffer.from("partial"));
    input.emit("data",Buffer.from([0x03]));
    await expect(pending).rejects.toThrow("Secret input cancelled");
    expect(input.rawModes).toEqual([true,false]);
    expect(output.writes.join("")).toBe("Credential: \n");
  });
});
