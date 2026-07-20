import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repository = dirname(dirname(fileURLToPath(import.meta.url)));
const source = join(repository, "web", "dist");
const destination = join(repository, "internal", "webui", "generated");

await mkdir(destination, { recursive: true });
for (const entry of await readdir(destination)) {
  if (entry !== ".placeholder") await rm(join(destination, entry), { recursive: true, force: true });
}
await cp(source, destination, { recursive: true });
