import { describe, expect, it } from "vitest";

import { detectLockfileFormat, validateEcosystem, validateEmail, validatePagination, validateReportType, validateChannel, validateRole, validateStringLength, validateVersion } from "./validation";

describe("validation", () => {
  describe("validateEcosystem", () => {
    it("accepts valid ecosystems", () => {
      expect(validateEcosystem("npm")).toBe(true);
      expect(validateEcosystem("pypi")).toBe(true);
      expect(validateEcosystem("crates")).toBe(true);
      expect(validateEcosystem("go")).toBe(true);
    });

    it("rejects invalid ecosystems", () => {
      expect(validateEcosystem("rubygems")).toBe(false);
      expect(validateEcosystem("")).toBe(false);
      expect(validateEcosystem("NPM")).toBe(false);
    });
  });

  describe("validateVersion", () => {
    it("accepts valid versions", () => {
      expect(validateVersion("1.0.0")).toBe(true);
      expect(validateVersion("v2.3.4")).toBe(true);
      expect(validateVersion("0.33.2-beta.1")).toBe(true);
    });

    it("rejects invalid versions", () => {
      expect(validateVersion("latest")).toBe(false);
      expect(validateVersion("")).toBe(false);
      expect(validateVersion("abc")).toBe(false);
    });
  });

  describe("validatePagination", () => {
    it("returns defaults when no params", () => {
      const result = validatePagination(undefined, undefined);
      expect(result).toEqual({ limit: 20, offset: 0 });
    });

    it("clamps limit to 1-100", () => {
      expect(validatePagination(0, 0)).toBe("limit must be 1-100");
      expect(validatePagination(101, 0)).toBe("limit must be 1-100");
      expect(validatePagination(50, 0)).toEqual({ limit: 50, offset: 0 });
    });

    it("rejects negative offset", () => {
      expect(validatePagination(10, -1)).toBe("offset must be >= 0");
    });
  });

  describe("validateReportType", () => {
    it("accepts valid types", () => {
      expect(validateReportType("soc2")).toBe(true);
      expect(validateReportType("iso27001")).toBe(true);
      expect(validateReportType("cra")).toBe(true);
      expect(validateReportType("custom")).toBe(true);
    });

    it("rejects invalid types", () => {
      expect(validateReportType("pci")).toBe(false);
      expect(validateReportType("")).toBe(false);
    });
  });

  describe("validateEmail", () => {
    it("accepts valid emails", () => {
      expect(validateEmail("user@example.com")).toBe(true);
      expect(validateEmail("a@b.co")).toBe(true);
    });

    it("rejects invalid emails", () => {
      expect(validateEmail("not-an-email")).toBe(false);
      expect(validateEmail("")).toBe(false);
      expect(validateEmail("@no-user.com")).toBe(false);
    });
  });

  describe("validateChannel", () => {
    it("accepts valid channels", () => {
      expect(validateChannel("email")).toBe(true);
      expect(validateChannel("slack")).toBe(true);
      expect(validateChannel("webhook")).toBe(true);
    });

    it("rejects invalid channels", () => {
      expect(validateChannel("sms")).toBe(false);
    });
  });

  describe("validateRole", () => {
    it("accepts valid roles", () => {
      expect(validateRole("admin")).toBe(true);
      expect(validateRole("member")).toBe(true);
      expect(validateRole("viewer")).toBe(true);
    });

    it("rejects invalid roles", () => {
      expect(validateRole("superadmin")).toBe(false);
    });
  });

  describe("validateStringLength", () => {
    it("returns null for valid strings", () => {
      expect(validateStringLength("hello", "name", 100)).toBeNull();
    });

    it("rejects non-strings", () => {
      expect(validateStringLength(123, "name", 100)).toBe("name must be a string");
    });

    it("rejects empty strings", () => {
      expect(validateStringLength("", "name", 100)).toBe("name must not be empty");
    });

    it("rejects strings exceeding max length", () => {
      expect(validateStringLength("a".repeat(101), "name", 100)).toBe("name must be at most 100 characters");
    });
  });

  describe("detectLockfileFormat", () => {
    it("detects npm from filename", () => {
      expect(detectLockfileFormat("package-lock.json", "{}")).toBe("npm");
      expect(detectLockfileFormat("npm-shrinkwrap.json", "{}")).toBe("npm");
    });

    it("detects yarn v1 from filename", () => {
      expect(detectLockfileFormat("yarn.lock", "# yarn lockfile v1\n")).toBe("yarn-v1");
    });

    it("detects yarn berry from content", () => {
      expect(detectLockfileFormat("yarn.lock", '__metadata:\n  version: 8')).toBe("yarn-berry");
    });

    it("detects pnpm from filename", () => {
      expect(detectLockfileFormat("pnpm-lock.yaml", "lockfileVersion: '9.0'")).toBe("pnpm");
    });

    it("returns null for unrecognized formats", () => {
      expect(detectLockfileFormat("unknown.txt", "random content")).toBeNull();
    });

    it("detects npm from JSON content", () => {
      expect(detectLockfileFormat("lockfile.json", '{"lockfileVersion": 3}')).toBe("npm");
    });

    it("detects pnpm from YAML content", () => {
      expect(detectLockfileFormat("deps.yaml", "lockfileVersion: '9.0'\npackages:")).toBe("pnpm");
    });
  });
});
