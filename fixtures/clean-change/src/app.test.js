import { fixtureValue } from "./app.js";

if (fixtureValue() !== "synthetic clean change") {
  throw new Error("fixture assertion failed");
}
