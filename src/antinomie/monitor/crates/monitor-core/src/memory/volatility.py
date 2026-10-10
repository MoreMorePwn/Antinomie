# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
# Runs Volatility 3 for Antinomie (python3 -I -c <this> LIB MODE ARGS...).
#   LIB   directory holding the volatility3 package and its dependencies
#   MODE  "describe [PLUGIN_DIR]": print every plugin with its options as
#         JSON, with those of PLUGIN_DIR (community plugins) marked, and the
#         plugin files that failed to load
#         "run": run the Volatility CLI with ARGS; "-r antinomie" streams
#         the result as JSON lines: {"columns": [...]} then {"d", "v"} rows.
import datetime
import json
import sys

sys.path.insert(0, sys.argv[1])
mode = sys.argv[2]
sys.argv = ["vol"] + sys.argv[3:]

import volatility3.framework as framework  # noqa: E402
from volatility3.framework import interfaces, renderers  # noqa: E402
from volatility3.framework.configuration import requirements  # noqa: E402
from volatility3.framework.renderers import format_hints  # noqa: E402


def describe():
    import inspect
    import os

    import volatility3.plugins
    from volatility3.framework import constants

    community = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else None
    if community:
        # As the CLI does for -p: extra folders first in the plugin path.
        volatility3.plugins.__path__ = [community] + constants.PLUGINS_PATH
    framework.require_interface_version(2, 0, 0)
    failures = framework.import_files(volatility3.plugins, True)
    kinds = [
        (requirements.BooleanRequirement, "bool"),
        (requirements.IntRequirement, "int"),
        (requirements.StringRequirement, "string"),
        (requirements.URIRequirement, "string"),
        (requirements.ChoiceRequirement, "choice"),
        (requirements.ListRequirement, "list"),
    ]
    plugins = []
    for name, plugin in sorted(framework.list_plugins().items()):
        options = []
        for requirement in plugin.get_requirements():
            kind = next((k for cls, k in kinds if isinstance(requirement, cls)), None)
            if kind is None:
                continue
            option = {
                "name": requirement.name,
                "kind": kind,
                "help": requirement.description or "",
                "optional": bool(requirement.optional),
            }
            if kind == "list":
                option["element"] = getattr(requirement.element_type, "__name__", "str")
            if kind == "choice":
                option["choices"] = [str(choice) for choice in requirement.choices]
            if requirement.default is not None and kind != "list":
                option["default"] = requirement.default
            options.append(option)
        text = (plugin.__doc__ or "").strip().split("\n\n")[0]
        try:
            source = os.path.abspath(inspect.getfile(plugin))
        except TypeError:
            source = ""
        plugins.append({
            "name": name,
            "help": " ".join(text.split()),
            "options": options,
            "community": bool(community) and source.startswith(community + os.sep),
        })
    ours = set()
    for root, _, files in os.walk(community) if community else ():
        for file in files:
            if file.endswith(".py"):
                relative = os.path.relpath(os.path.join(root, file[:-3]), community)
                ours.add("volatility3.plugins." + relative.replace(os.sep, "."))
    failed = sorted(str(name) for name in (failures or []) if str(name) in ours)
    json.dump({"plugins": plugins, "failures": failed}, sys.stdout)


def run():
    from volatility3 import cli
    from volatility3.cli import text_renderer

    def kind(column_type):
        if column_type is format_hints.Hex:
            return "hex"
        if column_type is format_hints.Bin:
            return "bin"
        if column_type is bool:
            return "bool"
        if isinstance(column_type, type) and issubclass(column_type, int):
            return "int"
        if column_type in (bytes, format_hints.HexBytes, renderers.LayerData):
            return "bytes"
        if column_type is datetime.datetime:
            return "time"
        if column_type is renderers.Disassembly:
            return "disasm"
        return "str"

    class AntinomieRenderer(text_renderer.CLIRenderer):
        name = "antinomie"
        structured_output = True
        _type_renderers = text_renderer.JsonRenderer._type_renderers

        def get_render_options(self):
            return []

        def render(self, grid):
            out = sys.stdout
            columns = [
                {"name": column.name, "type": kind(column.type)} for column in grid.columns
            ]
            out.write(json.dumps({"columns": columns}) + "\n")
            out.flush()
            written = [0]

            def visit(node, accumulator):
                values = []
                for index, column in enumerate(grid.columns):
                    value = node.values[index]
                    if isinstance(value, interfaces.renderers.BaseAbsentValue):
                        values.append({"absent": type(value).__name__})
                        continue
                    render = self._type_renderers.get(
                        column.type, self._type_renderers["default"]
                    )
                    value = render(value)
                    if isinstance(value, datetime.datetime):
                        value = value.isoformat()
                    elif not isinstance(value, (int, float, str, bool, type(None))):
                        value = str(value)
                    values.append(value)
                out.write(json.dumps({"d": node.path_depth - 1, "v": values}) + "\n")
                written[0] += 1
                if written[0] % 256 == 0:
                    out.flush()
                return accumulator

            if not grid.populated:
                grid.populate(visit, None)
            else:
                grid.visit(None, visit, None)
            out.flush()

    cli.main()


describe() if mode == "describe" else run()
