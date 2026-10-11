import json
import subprocess
from os import environ

from scanpipe.pipes import atom
from scanpipe.pipes import run_command_safely
from scanpipe.pipes.reachability_tools import ReachabilityPipeline
from scanpipe.pipes.reachability_tools import ReachabilityTool

ATOM_EXECUTABLE = environ.get("ATOM_EXECUTABLE")


class AtomTool(ReachabilityTool):
    tool_name = "atom"
    executable = ATOM_EXECUTABLE
    supported_languages = ("Python",)
    atom_language = "python"

    @classmethod
    def get_availability(cls):
        if not cls.executable:
            return "atom is not configured. Set the ATOM_EXECUTABLE environment variable."

    @classmethod
    def get_target_path(cls, project):
        target_path = project.codebase_path
        if target_path:
            return target_path
        resource = project.codebaseresources.filter(
            is_binary=False,
            is_archive=False,
            is_media=False,
            programming_language__in=cls.supported_languages,
        ).first()
        if not resource:
            raise ValueError("No codebase resources found for this project.")
        return resource.location_path

    @classmethod
    def run_atom_command(cls, kind, target_path, manifest_path, logger):
        """Run one atom command; return the slices file path, or None on failure."""
        prefix = f"{manifest_path.stem}.{cls.atom_language}"
        slice_path = manifest_path.with_name(f"{prefix}.{kind}.slices.json")
        atom_path = manifest_path.with_name(f"{prefix}.atom")
        command_args = [
            cls.executable, kind,
            "-l", cls.atom_language,
            "-o", str(atom_path),
            "-s", str(slice_path),
            str(target_path),
        ]

        logger(f"Running atom {kind} on {target_path} ...")
        try:
            run_command_safely(command_args=command_args)
        except subprocess.SubprocessError as error:
            logger(f"atom {kind} failed: {error!r}")
            return None
        if not slice_path.exists():
            logger(f"atom {kind} did not generate {slice_path}")
            return None
        return slice_path

    @classmethod
    def run(cls, project, logger=None):
        """Run atom and return the path of the generated manifest of slices."""
        target_path = cls.get_target_path(project)
        manifest_path = project.get_output_file_path("atom_reachability", "json")

        slices = {}
        for kind in ("usages", "reachables"):
            slice_path = cls.run_atom_command(
                kind=kind,
                target_path=target_path,
                manifest_path=manifest_path,
                logger=logger,
            )
            if slice_path:
                slices[kind] = str(slice_path)
            else:
                logger(f"atom {kind} failed; its symbols will be UNKNOWN")

        with open(manifest_path, "w") as manifest_file:
            json.dump(slices, manifest_file, indent=2)
        return manifest_path

    @classmethod
    def parsed_output(cls, export_output_path, logger=None):
        """Load the manifest and the slices it points to."""
        with open(export_output_path) as manifest_file:
            manifest = json.load(manifest_file)

        resource_indexes = {}
        for kind, slice_path in manifest.items():
            try:
                with open(slice_path) as slice_file:
                    resource_indexes[kind] = json.load(slice_file)
            except (FileNotFoundError, json.JSONDecodeError) as error:
                if logger:
                    logger(f"Skipping {kind} atom slices: {error!r}")
        return resource_indexes

class AtomReachability(ReachabilityPipeline):
    """
    Determine the reachability of vulnerabilities using the atom tool.

    Note: You must run the ``find_vulnerabilities`` pipeline before running
    this pipeline.

    atom is run once per language to generate a ``usages`` slice (and, best
    effort, a ``reachables`` slice) of the project codebase. The vulnerable
    and fixed symbols of each patch are matched against those slices with
    dot-boundary suffix matching:

    - REACHABLE: the symbol is in a ``reachables`` flow, or has a call site in
      non-test code (no entry-point path is proven)
    - NOT_REACHABLE: the symbol is absent, or only used in tests
    - UNKNOWN: atom failed for a language, or the symbol is defined in non-test
      code but never called, so absence proves nothing

    Results are stored in the ``extra_data`` of the matching resources under
    the ``symbols_reachability`` key.
    """

    reachability_tool = AtomTool

    @classmethod
    def get_availability(cls):
        return cls.reachability_tool.get_availability()

    def get_candidate_resources(self):
        """Collect candidate resources for this pipeline."""
        self.candidate_resources = self.project.codebaseresources.files().filter(
            is_binary=False,
            is_archive=False,
            is_media=False,
            programming_language__in=self.reachability_tool.supported_languages,
        )

    def collect_resource_index(self):
        """Generate the atom slices and load them."""
        self.resource_indexes_path = self.reachability_tool.run(
            project=self.project, logger=self.log
        )
        self.resource_indexes = self.reachability_tool.parsed_output(
            export_output_path=self.resource_indexes_path, logger=self.log
        )

    def collect_and_match_resources(self):
        """Match patch symbols against the atom slices."""
        self.symbol_results = atom.match_patches_to_resources(
            tool_name=self.reachability_tool.tool_name,
            patches=self.patches,
            patch_symbols=self.patch_symbols,
            resource_indexes=self.resource_indexes,
            candidate_resources=self.candidate_resources,
            logger=self.log,
        )
