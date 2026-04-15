package io.cryptograph.exporter

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import java.io.File
import java.nio.file.Files
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.isRegularFile

data class GraphNode(
    val id: String,
    val kind: String,
    val name: String?,
    val file: String,
    val line: Int?,
    val function: String?,
    val properties: Map<String, Any?> = emptyMap(),
)

data class GraphEdge(
    val source: String,
    val target: String,
    val kind: String,
)

data class NormalizedGraph(
    val backend: String,
    val root: String,
    val nodes: List<GraphNode>,
    val edges: List<GraphEdge> = emptyList(),
)

fun main(args: Array<String>) {
    val input = option(args, "--input") ?: error("--input is required")
    val output = option(args, "--output") ?: error("--output is required")
    val root = Path(input)
    val files = pythonFiles(root)

    val graph =
        try {
            buildFraunhoferCpgGraph(root, files)
        } catch (error: Throwable) {
            System.err.println(
                "[cryptograph-exporter] Fraunhofer CPG traversal failed; using source boundary fallback: ${error.message}",
            )
            buildSourceBoundaryGraph(root, files)
        }

    jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValue(File(output), graph)
}

private fun pythonFiles(root: java.nio.file.Path): List<java.nio.file.Path> {
    return if (root.isRegularFile()) {
        listOf(root).filter { it.toString().endsWith(".py") }
    } else {
        Files.walk(root).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.toString().endsWith(".py") }.toList()
        }
    }
}

private fun buildFraunhoferCpgGraph(
    root: java.nio.file.Path,
    files: List<java.nio.file.Path>,
): NormalizedGraph {
    val config =
        TranslationConfiguration.Companion.builder()
            .sourceLocations(files.map { it.toFile() })
            .topLevel(if (root.isRegularFile()) root.parent.toFile() else root.toFile())
            .registerLanguage(PythonLanguage())
            .codeInNodes(true)
            .failOnError(false)
            .build()

    val result = TranslationManager.builder().config(config).build().analyze().get()
    val calls =
        result.translationUnits
            .flatMap { flattenAst(it) }
            .filterIsInstance<CallExpression>()
            .toList()
    val functions =
        result.translationUnits
            .flatMap { flattenAst(it) }
            .filterIsInstance<FunctionDeclaration>()
            .toList()

    val nodes = linkedMapOf<String, GraphNode>()
    val edges = linkedSetOf<GraphEdge>()

    calls.forEach { call -> addCallSubgraph(call, nodes, edges) }
    addCallGraphEdges(calls, functions, nodes, edges)

    return NormalizedGraph("fraunhofer-cpg", root.absolutePathString(), nodes.values.toList(), edges.toList())
}

private fun flattenAst(node: Node): Sequence<Node> =
    sequence {
        yield(node)
        node.astChildren.forEach { child -> yieldAll(flattenAst(child)) }
    }

private fun addCallSubgraph(
    call: CallExpression,
    nodes: LinkedHashMap<String, GraphNode>,
    edges: LinkedHashSet<GraphEdge>,
) {
    val callNode = call.toCallGraphNode()
    nodes.putIfAbsent(callNode.id, callNode)

    val function = nearestFunction(call)
    if (function != null) {
        val functionNode = function.toGenericGraphNode("function")
        nodes.putIfAbsent(functionNode.id, functionNode)
        edges.add(GraphEdge(functionNode.id, callNode.id, "AST_FUNCTION"))
    }

    call.callee?.let { callee ->
        val calleeNode = callee.toGenericGraphNode("callee")
        nodes.putIfAbsent(calleeNode.id, calleeNode)
        edges.add(GraphEdge(callNode.id, calleeNode.id, "AST_CALLEE"))
    }

    call.arguments.forEachIndexed { index, argument ->
        val argumentNode = argument.toGenericGraphNode("argument")
        nodes.putIfAbsent(argumentNode.id, argumentNode)
        edges.add(GraphEdge(callNode.id, argumentNode.id, "AST_ARGUMENT_$index"))
    }

    call.prevDFG.forEach { previous ->
        val previousNode = previous.toGenericGraphNode("dfg")
        nodes.putIfAbsent(previousNode.id, previousNode)
        edges.add(GraphEdge(previousNode.id, callNode.id, "DFG"))
    }
    call.nextDFG.forEach { next ->
        val nextNode = next.toGenericGraphNode("dfg")
        nodes.putIfAbsent(nextNode.id, nextNode)
        edges.add(GraphEdge(callNode.id, nextNode.id, "DFG"))
    }

    call.prevEOG.forEach { previous ->
        val previousNode = previous.toGenericGraphNode("eog")
        nodes.putIfAbsent(previousNode.id, previousNode)
        edges.add(GraphEdge(previousNode.id, callNode.id, "EOG"))
    }
    call.nextEOG.forEach { next ->
        val nextNode = next.toGenericGraphNode("eog")
        nodes.putIfAbsent(nextNode.id, nextNode)
        edges.add(GraphEdge(callNode.id, nextNode.id, "EOG"))
    }
}

private fun addCallGraphEdges(
    calls: List<CallExpression>,
    functions: List<FunctionDeclaration>,
    nodes: LinkedHashMap<String, GraphNode>,
    edges: LinkedHashSet<GraphEdge>,
) {
    val functionsByName = functions.associateBy { it.name.toString() }
    val functionsByShortName = functions.associateBy { it.name.toString().substringAfterLast('.') }

    calls.forEach { call ->
        val caller = nearestFunction(call) ?: return@forEach
        val callerNode = caller.toGenericGraphNode("function")
        nodes.putIfAbsent(callerNode.id, callerNode)

        val invokeTargets = call.invokes
        if (invokeTargets.isNotEmpty()) {
            invokeTargets.forEach { target ->
                val targetNode = target.toGenericGraphNode("function")
                nodes.putIfAbsent(targetNode.id, targetNode)
                if (callerNode.id != targetNode.id) {
                    edges.add(GraphEdge(callerNode.id, targetNode.id, "CALLS"))
                }
            }
            return@forEach
        }

        val calleeName = (call.callee?.code ?: call.callee?.name?.toString() ?: call.name.toString())
            .substringBefore("(")
            .substringAfterLast(".")
        val target = functionsByName[calleeName] ?: functionsByShortName[calleeName]
        if (target != null) {
            val targetNode = target.toGenericGraphNode("function")
            nodes.putIfAbsent(targetNode.id, targetNode)
            if (callerNode.id != targetNode.id) {
                edges.add(GraphEdge(callerNode.id, targetNode.id, "CALLS"))
            }
        }
    }
}

private fun CallExpression.toCallGraphNode(): GraphNode {
    val arguments = this.arguments.map { argument ->
        argument.code?.ifBlank { argument.name.toString() } ?: argument.name.toString()
    }
    val function = nearestFunction(this)?.name?.toString()
    val inferredFile = this.file ?: inferFileFromFunction(function)
    val line = this.location?.region?.startLine

    return GraphNode(
        id = normalizedNodeId(this),
        kind = "call",
        name = this.name.toString(),
        file = inferredFile ?: "",
        line = line,
        function = function,
        properties = mapOf(
            "arguments" to arguments,
            "resolved_name" to this.name.toString(),
            "callee" to (this.callee?.code ?: this.callee?.name?.toString()),
            "invokes" to this.invokes.map { it.name.toString() },
            "prev_dfg" to this.prevDFG.map { it.name.toString() },
            "next_dfg" to this.nextDFG.map { it.name.toString() },
            "literal_arguments" to arguments.filter { isStringLiteral(it) },
        ),
    )
}

private fun Node.toGenericGraphNode(kind: String): GraphNode {
    val function = nearestFunction(this)?.name?.toString()
    val inferredFile = this.file ?: inferFileFromFunction(function)
    return GraphNode(
        id = normalizedNodeId(this),
        kind = kind,
        name = this.name.toString(),
        file = inferredFile ?: "",
        line = this.location?.region?.startLine,
        function = function,
        properties = mapOf(
            "code" to this.code,
            "cpg_type" to this::class.simpleName,
            "argument_index" to this.argumentIndex.takeIf { it >= 0 },
            "prev_dfg" to this.prevDFG.map { it.name.toString() },
            "next_dfg" to this.nextDFG.map { it.name.toString() },
            "prev_eog" to this.prevEOG.map { it.name.toString() },
            "next_eog" to this.nextEOG.map { it.name.toString() },
        ),
    )
}

private fun normalizedNodeId(node: Node): String {
    val stablePart = listOfNotNull(
        node.file ?: inferFileFromFunction(nearestFunction(node)?.name?.toString()),
        node.location?.region?.startLine?.toString(),
        node::class.simpleName,
        node.name.toString(),
        node.code,
    ).joinToString(":")
    return "$stablePart:${System.identityHashCode(node)}"
}

private fun nearestFunction(node: Node): FunctionDeclaration? {
    return generateSequence(node.astParent) { it.astParent }
        .filterIsInstance<FunctionDeclaration>()
        .firstOrNull()
}

private fun inferFileFromFunction(function: String?): String? {
    val module = function?.substringBefore('.', missingDelimiterValue = "")?.takeIf { it.isNotBlank() }
    return module?.let { "$it.py" }
}

private fun buildSourceBoundaryGraph(
    root: java.nio.file.Path,
    files: List<java.nio.file.Path>,
): NormalizedGraph {
    val files =
        if (files.isEmpty() && root.isRegularFile()) listOf(root) else files
    val nodes = files.flatMap { file ->
        var currentFunction: String? = null
        File(file.absolutePathString()).readLines().mapIndexedNotNull { index, line ->
            functionName(line)?.let { currentFunction = it }
            val callName = knownCalls.firstOrNull { line.contains("$it(") }
            if (callName == null) {
                null
            } else {
                val arguments = extractArguments(line, callName)
                GraphNode(
                    id = "${file.absolutePathString()}:${index + 1}",
                    kind = "call",
                    name = callName,
                    file = file.toString(),
                    line = index + 1,
                    function = currentFunction,
                    properties = mapOf(
                        "arguments" to arguments,
                        "resolved_name" to callName,
                        "literal_arguments" to arguments.filter { isStringLiteral(it) },
                    ),
                )
            }
        }
    }
    return NormalizedGraph("fraunhofer-cpg-boundary", root.absolutePathString(), nodes)
}

private val knownCalls = listOf(
    "AES.new",
    "PKCS1_OAEP.new",
    "RSA.generate",
    "hashlib.sha256",
    "hashlib.sha1",
    "hashlib.md5",
    "hashlib.pbkdf2_hmac",
    "hmac.new",
    "Fernet.generate_key",
    "Fernet",
    "secrets.token_bytes",
    "os.urandom",
    "random.randbytes",
)

private fun option(args: Array<String>, name: String): String? {
    val index = args.indexOf(name)
    return if (index >= 0 && index + 1 < args.size) args[index + 1] else null
}

private fun functionName(line: String): String? {
    val match = Regex("""^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(""").find(line)
    return match?.groupValues?.get(1)
}

private fun extractArguments(line: String, callName: String): List<String> {
    val start = line.indexOf("$callName(")
    if (start < 0) {
        return emptyList()
    }
    val argsStart = start + callName.length + 1
    val args = StringBuilder()
    var depth = 0
    var quote: Char? = null
    var escaped = false

    for (index in argsStart until line.length) {
        val char = line[index]
        if (quote != null) {
            args.append(char)
            if (escaped) {
                escaped = false
            } else if (char == '\\') {
                escaped = true
            } else if (char == quote) {
                quote = null
            }
            continue
        }
        when (char) {
            '\'', '"' -> {
                quote = char
                args.append(char)
            }
            '(' -> {
                depth += 1
                args.append(char)
            }
            ')' -> {
                if (depth == 0) {
                    return splitArguments(args.toString())
                }
                depth -= 1
                args.append(char)
            }
            else -> args.append(char)
        }
    }
    return splitArguments(args.toString())
}

private fun splitArguments(raw: String): List<String> {
    val result = mutableListOf<String>()
    val current = StringBuilder()
    var depth = 0
    var quote: Char? = null
    var escaped = false

    for (char in raw) {
        if (quote != null) {
            current.append(char)
            if (escaped) {
                escaped = false
            } else if (char == '\\') {
                escaped = true
            } else if (char == quote) {
                quote = null
            }
            continue
        }
        when (char) {
            '\'', '"' -> {
                quote = char
                current.append(char)
            }
            '(', '[', '{' -> {
                depth += 1
                current.append(char)
            }
            ')', ']', '}' -> {
                depth -= 1
                current.append(char)
            }
            ',' -> {
                if (depth == 0) {
                    current.toString().trim().takeIf { it.isNotEmpty() }?.let { result.add(it) }
                    current.clear()
                } else {
                    current.append(char)
                }
            }
            else -> current.append(char)
        }
    }
    current.toString().trim().takeIf { it.isNotEmpty() }?.let { result.add(it) }
    return result
}

private fun isStringLiteral(value: String): Boolean {
    val trimmed = value.trim()
    return (trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
        (trimmed.startsWith("'") && trimmed.endsWith("'"))
}
