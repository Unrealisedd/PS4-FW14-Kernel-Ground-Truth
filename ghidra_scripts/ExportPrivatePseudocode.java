// Run from Ghidra 12.1.3: output-dir start count timeout-seconds
// @category PS4
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;

public class ExportPrivatePseudocode extends GhidraScript {
    private static final String EXPECTED_SHA256 = "b20a94820aef512490d6167497eb00f9eaa5c780814fe19361b4f00cb7713c3b";
    private static final String EXPECTED_GHIDRA_VERSION = "12.1.3";
    private static final int EXPECTED_FUNCTIONS = 19809;
    private static final String HEADER = "index\tstatus\taddress\tname\tsignature\terror\n";
    private static String preamble(String programHash, int start, int count) {
        return "# schema=ps4-fw14-private-shard.v1\n" +
            "# program_sha256=" + programHash.toLowerCase() + "\n" +
            "# ghidra_version=" + EXPECTED_GHIDRA_VERSION + "\n" +
            "# start=" + start + "\n" +
            "# count=" + count + "\n";
    }

    private static String cell(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static boolean within(Path child, Path parent) {
        return child.toAbsolutePath().normalize().startsWith(parent.toAbsolutePath().normalize());
    }

    private static void rejectLinkedComponents(Path path) throws IOException {
        Path absolute = path.toAbsolutePath().normalize();
        Path cursor = absolute.getRoot();
        for (Path part : absolute) {
            cursor = cursor.resolve(part);
            if (!Files.exists(cursor, LinkOption.NOFOLLOW_LINKS)) continue;
            BasicFileAttributes attributes = Files.readAttributes(
                cursor, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink() || attributes.isOther()) {
                throw new SecurityException("output path contains a symlink, junction, or reparse entry: " + cursor);
            }
        }
    }

    private static Path canonicalDirectory(Path requested) throws IOException {
        rejectLinkedComponents(requested);
        Files.createDirectories(requested);
        rejectLinkedComponents(requested);
        Path canonical = requested.toRealPath(LinkOption.NOFOLLOW_LINKS);
        BasicFileAttributes attributes = Files.readAttributes(
            canonical, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new SecurityException("output is not a regular directory");
        }
        return canonical;
    }

    private static void regularFile(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
            path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new SecurityException("path is not a regular file: " + path);
        }
    }

    private static void directory(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
            path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new SecurityException("path is not a regular directory: " + path);
        }
    }

    private static final class FileIdentity {
        final Path path;
        final Path anchor;

        FileIdentity(Path path, Path anchor) {
            this.path = path;
            this.anchor = anchor;
        }
    }

    private static final class DirectoryIdentity {
        final Path path;
        final FileIdentity marker;

        DirectoryIdentity(Path path, FileIdentity marker) {
            this.path = path;
            this.marker = marker;
        }
    }

    private static FileIdentity identifyFile(Path path, Path anchorDirectory) throws IOException {
        regularFile(path);
        directory(anchorDirectory);
        Path anchor = anchorDirectory.resolve(
            ".fw14-file-identity-" + UUID.randomUUID() + ".lock");
        try {
            Files.createLink(anchor, path);
            regularFile(anchor);
            if (!Files.isSameFile(path, anchor)) {
                throw new SecurityException("hard-link identity check failed for " + path);
            }
            return new FileIdentity(path, anchor);
        }
        catch (Exception failure) {
            try {
                Files.deleteIfExists(anchor);
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to create file identity anchor", failure);
        }
    }

    private static FileIdentity createIdentifiedFile(Path path, Path anchorDirectory)
            throws IOException {
        Files.createFile(path);
        try {
            return identifyFile(path, anchorDirectory);
        }
        catch (Exception failure) {
            try {
                Files.deleteIfExists(path);
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to create identified file", failure);
        }
    }

    private static FileIdentity createIdentifiedTempFile(
            Path directory, String prefix, String suffix) throws IOException {
        Path path = Files.createTempFile(directory, prefix, suffix);
        try {
            return identifyFile(path, directory);
        }
        catch (Exception failure) {
            try {
                Files.deleteIfExists(path);
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to create identified temporary file", failure);
        }
    }

    private static void requireSame(FileIdentity identity) throws IOException {
        regularFile(identity.path);
        regularFile(identity.anchor);
        if (!Files.isSameFile(identity.path, identity.anchor)) {
            throw new SecurityException("path object identity changed: " + identity.path);
        }
    }

    private static DirectoryIdentity identifyDirectory(Path path, Path anchorDirectory)
            throws IOException {
        directory(path);
        Path marker = Files.createTempFile(path, ".fw14-directory-identity-", ".lock");
        FileIdentity markerIdentity = null;
        try {
            markerIdentity = identifyFile(marker, anchorDirectory);
            DirectoryIdentity identity = new DirectoryIdentity(path, markerIdentity);
            requireSame(identity);
            return identity;
        }
        catch (Exception failure) {
            try {
                if (markerIdentity == null) Files.deleteIfExists(marker);
                else deleteOwned(markerIdentity);
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to create directory identity marker", failure);
        }
    }

    private static void requireSame(DirectoryIdentity identity) throws IOException {
        directory(identity.path);
        if (!identity.marker.path.getParent().equals(identity.path)) {
            throw new SecurityException("directory identity marker escaped its directory");
        }
        requireSame(identity.marker);
    }

    private static IOException ioFailure(String message, Exception failure) {
        if (failure instanceof IOException) return (IOException) failure;
        if (failure instanceof RuntimeException) throw (RuntimeException) failure;
        return new IOException(message, failure);
    }

    private static final class Stage {
        final DirectoryIdentity output;
        final DirectoryIdentity directory;

        Stage(DirectoryIdentity output, DirectoryIdentity directory) {
            this.output = output;
            this.directory = directory;
        }
    }

    private static Stage createStage(DirectoryIdentity output) throws IOException {
        requireSame(output);
        Path stage = Files.createTempDirectory(output.path, ".fw14-kernel-stage-");
        DirectoryIdentity stageIdentity = null;
        try {
            try {
                Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("rwx------"));
            }
            catch (UnsupportedOperationException ignored) {
                // Windows inherits the ACL of the required trusted, owner-controlled parent.
            }
            stageIdentity = identifyDirectory(stage, output.path);
            requireSame(output);
            requireSame(stageIdentity);
            return new Stage(output, stageIdentity);
        }
        catch (Exception failure) {
            if (stageIdentity != null) {
                try {
                    deleteDirectoryIdentity(stageIdentity);
                }
                catch (IOException cleanup) {
                    failure.addSuppressed(cleanup);
                }
            }
            try {
                Files.deleteIfExists(stage);
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to create private staging directory", failure);
        }
    }

    private static FileChannel openBoundChannel(FileIdentity identity, Stage stage)
            throws IOException {
        FileChannel channel = FileChannel.open(
            identity.path, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        byte[] nonce = UUID.randomUUID().toString().getBytes(StandardCharsets.US_ASCII);
        try {
            channel.write(ByteBuffer.wrap(nonce));
            channel.force(true);
            requireSame(stage.output);
            requireSame(stage.directory);
            requireSame(identity);
            if (!Arrays.equals(nonce, Files.readAllBytes(identity.path))) {
                throw new SecurityException("temporary file handle is not bound to its path");
            }
            channel.truncate(0);
            channel.position(0);
            return channel;
        }
        catch (Exception failure) {
            try {
                channel.close();
            }
            catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw ioFailure("failed to bind private temporary file", failure);
        }
    }

    private static FileIdentity commitNoClobber(
            FileIdentity source, Path target, Stage stage) throws IOException {
        requireSame(stage.output);
        requireSame(stage.directory);
        requireSame(source);
        boolean created = false;
        FileIdentity published = new FileIdentity(target, source.anchor);
        try {
            Files.createLink(target, source.path);
            created = true;
            requireSame(stage.output);
            requireSame(stage.directory);
            requireSame(published);
            Files.delete(source.path);
            requireSame(published);
            return published;
        }
        catch (Exception failure) {
            if (created) {
                try {
                    requireSame(published);
                    Files.delete(target);
                }
                catch (Exception cleanup) {
                    failure.addSuppressed(new IOException(
                        "contamination: could not safely remove staged target " + target, cleanup));
                }
            }
            throw ioFailure("failed to publish validated shard artifact", failure);
        }
    }

    private static void deleteOwned(FileIdentity identity) throws IOException {
        if (identity == null) return;
        IOException failure = null;
        if (Files.exists(identity.path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                requireSame(identity);
                Files.delete(identity.path);
            }
            catch (Exception cleanup) {
                failure = new IOException("could not safely remove owned file " + identity.path,
                    cleanup);
            }
        }
        if (Files.exists(identity.anchor, LinkOption.NOFOLLOW_LINKS)) {
            try {
                regularFile(identity.anchor);
                Files.delete(identity.anchor);
            }
            catch (Exception cleanup) {
                IOException wrapped = new IOException(
                    "could not safely remove file identity anchor " + identity.anchor, cleanup);
                if (failure == null) failure = wrapped;
                else failure.addSuppressed(wrapped);
            }
        }
        if (failure != null) throw failure;
    }

    private static void deleteAnchor(FileIdentity identity) throws IOException {
        if (identity == null || !Files.exists(identity.anchor, LinkOption.NOFOLLOW_LINKS)) return;
        requireSame(identity);
        Files.delete(identity.anchor);
    }

    private static void deleteDirectoryIdentity(DirectoryIdentity identity) throws IOException {
        if (identity == null) return;
        requireSame(identity);
        deleteOwned(identity.marker);
    }

    private static void deleteStage(Stage stage) throws IOException {
        if (stage == null || !Files.exists(stage.directory.path, LinkOption.NOFOLLOW_LINKS)) return;
        requireSame(stage.output);
        requireSame(stage.directory);
        deleteDirectoryIdentity(stage.directory);
        Files.delete(stage.directory.path);
    }

    @FunctionalInterface
    private interface Cleanup {
        void run() throws Exception;
    }

    private static IOException cleanup(IOException prior, String label, Cleanup action) {
        try {
            action.run();
        }
        catch (Exception failure) {
            IOException wrapped = new IOException("cleanup failed for " + label, failure);
            if (prior == null) return wrapped;
            prior.addSuppressed(wrapped);
        }
        return prior;
    }

    @Override
    public void run() throws Exception {
        if (!EXPECTED_GHIDRA_VERSION.equals(Application.getApplicationVersion())) {
            throw new SecurityException("this exporter requires Ghidra " + EXPECTED_GHIDRA_VERSION);
        }
        String programHash = currentProgram.getExecutableSHA256();
        if (programHash == null || programHash.trim().isEmpty() ||
                !EXPECTED_SHA256.equalsIgnoreCase(programHash.trim())) {
            throw new SecurityException("imported Program SHA-256 does not match the prepared analysis ELF");
        }

        String[] arguments = getScriptArgs();
        if (arguments.length != 4) {
            throw new IllegalArgumentException("arguments: output-dir start count timeout-seconds");
        }
        Path requestedOutput = Paths.get(arguments[0]).toAbsolutePath().normalize();
        long startLong = Long.parseLong(arguments[1]);
        long countLong = Long.parseLong(arguments[2]);
        int timeout = Integer.parseInt(arguments[3]);
        if (startLong < 0 || countLong < 1 || countLong > 10000 ||
                startLong > Integer.MAX_VALUE || startLong + countLong < startLong ||
                startLong + countLong > EXPECTED_FUNCTIONS || timeout < 1 || timeout > 600) {
            throw new IllegalArgumentException(
                "bounds: start>=0, 1<=count<=10000, end<=19809, 1<=timeout<=600");
        }
        int start = (int) startLong;
        int count = (int) countLong;

        Path script = Paths.get(getSourceFile().getCanonicalPath()).toAbsolutePath().normalize();
        Path repository = script.getParent().getParent().toRealPath();
        Path project = Paths.get(
            state.getProject().getProjectLocator().getProjectDir().getCanonicalPath()).toRealPath();
        if (within(requestedOutput, repository) || within(requestedOutput, project)) {
            throw new SecurityException("output must be outside the script repository and Ghidra project");
        }
        Path output = canonicalDirectory(requestedOutput);
        directory(output);
        if (within(output, repository) || within(output, project)) {
            throw new SecurityException("output must be outside the script repository and Ghidra project");
        }

        List<Function> functions = new ArrayList<>();
        currentProgram.getFunctionManager().getFunctions(true).forEachRemaining(functions::add);
        functions.sort(Comparator.comparing(Function::getEntryPoint));
        if (functions.size() != EXPECTED_FUNCTIONS) {
            throw new IllegalStateException(
                "expected exactly " + EXPECTED_FUNCTIONS + " functions, found " + functions.size());
        }

        String stem = String.format("shard-%06d-%06d", start, count);
        Path metadata = output.resolve(stem + ".metadata.tsv");
        Path pseudocode = output.resolve(stem + ".pseudocode.txt.gz");
        if (Files.exists(metadata, LinkOption.NOFOLLOW_LINKS) ||
                Files.exists(pseudocode, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("refusing to overwrite shard");
        }

        Path reservation = output.resolve(stem + ".lock");
        DirectoryIdentity outputIdentity = null;
        FileIdentity reservationIdentity = null;
        Stage stage = null;
        FileIdentity metadataIdentity = null;
        FileIdentity pseudocodeIdentity = null;
        boolean pseudocodeCommitted = false;
        boolean metadataCommitted = false;
        DecompInterface decompiler = null;
        Exception primaryFailure = null;
        try {
            outputIdentity = identifyDirectory(output, output);
            try {
                reservationIdentity = createIdentifiedFile(reservation, output);
            }
            catch (FileAlreadyExistsException error) {
                throw new IOException(
                    "shard export is already running or requires stale-lock review", error);
            }
            requireSame(outputIdentity);
            stage = createStage(outputIdentity);

            metadataIdentity = createIdentifiedTempFile(
                stage.directory.path, ".metadata-", ".tmp");
            pseudocodeIdentity = createIdentifiedTempFile(
                stage.directory.path, ".pseudocode-", ".tmp");

            decompiler = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) {
                throw new IOException("decompiler rejected the current Program");
            }

            try (FileChannel metadataChannel =
                        openBoundChannel(metadataIdentity, stage);
                 FileChannel pseudocodeChannel =
                        openBoundChannel(pseudocodeIdentity, stage);
                 BufferedWriter metadataWriter = new BufferedWriter(new OutputStreamWriter(
                        Channels.newOutputStream(metadataChannel), StandardCharsets.UTF_8));
                 BufferedWriter pseudocodeWriter = new BufferedWriter(new OutputStreamWriter(
                        new GZIPOutputStream(Channels.newOutputStream(pseudocodeChannel)),
                        StandardCharsets.UTF_8))) {
                metadataWriter.write(preamble(programHash.trim(), start, count));
                metadataWriter.write(HEADER);
                for (int index = start; index < start + count; index++) {
                    monitor.checkCancelled();
                    Function function = functions.get(index);
                    String status = "ok";
                    String text = "";
                    String error = "";
                    try {
                        DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                        monitor.checkCancelled();
                        if (!result.decompileCompleted()) {
                            status = "decompile_failed";
                            error = result.getErrorMessage();
                        }
                        else {
                            text = result.getDecompiledFunction().getC();
                        }
                    }
                    catch (CancelledException cancelled) {
                        throw cancelled;
                    }
                    catch (RuntimeException failure) {
                        status = "decompile_failed";
                        error = failure.toString();
                    }
                    metadataWriter.write(index + "\t" + status + "\t" +
                        cell(function.getEntryPoint().toString()) + "\t" +
                        cell(function.getName()) + "\t" +
                        cell(function.getSignature().getPrototypeString()) + "\t" +
                        cell(error) + "\n");
                    pseudocodeWriter.write("===== " + "FUNCTION " + index + " =====\n");
                    pseudocodeWriter.write(text);
                    pseudocodeWriter.write("\n");
                }
                monitor.checkCancelled();
            }

            requireSame(outputIdentity);
            requireSame(stage.directory);
            requireSame(metadataIdentity);
            requireSame(pseudocodeIdentity);
            if (Files.size(metadataIdentity.path) <= HEADER.length() + 128 ||
                    Files.size(pseudocodeIdentity.path) == 0) {
                throw new IOException("incomplete temporary shard artifacts");
            }

            Path revalidatedOutput = requestedOutput.toRealPath(LinkOption.NOFOLLOW_LINKS);
            if (!revalidatedOutput.equals(output) ||
                    within(revalidatedOutput, repository) ||
                    within(revalidatedOutput, project) ||
                    Files.exists(metadata, LinkOption.NOFOLLOW_LINKS) ||
                    Files.exists(pseudocode, LinkOption.NOFOLLOW_LINKS)) {
                throw new SecurityException("output path changed or became unsafe before commit");
            }
            requireSame(outputIdentity);

            pseudocodeIdentity = commitNoClobber(
                pseudocodeIdentity, pseudocode, stage);
            pseudocodeCommitted = true;
            metadataIdentity = commitNoClobber(
                metadataIdentity, metadata, stage);
            metadataCommitted = true;
        }
        catch (Exception failure) {
            primaryFailure = failure;
            throw failure;
        }
        finally {
            final DecompInterface cleanupDecompiler = decompiler;
            final FileIdentity cleanupMetadataIdentity = metadataIdentity;
            final FileIdentity cleanupPseudocodeIdentity = pseudocodeIdentity;
            final boolean cleanupPseudocodeCommitted = pseudocodeCommitted;
            final boolean cleanupMetadataCommitted = metadataCommitted;
            final boolean cleanupSuccessful =
                primaryFailure == null && metadataCommitted && pseudocodeCommitted;
            final FileIdentity cleanupReservationIdentity = reservationIdentity;
            final Stage cleanupStage = stage;
            final DirectoryIdentity cleanupOutputIdentity = outputIdentity;

            IOException cleanupFailure = null;
            cleanupFailure = cleanup(cleanupFailure, "decompiler", () -> {
                if (cleanupDecompiler != null) cleanupDecompiler.dispose();
            });
            cleanupFailure = cleanup(cleanupFailure, "metadata artifact", () -> {
                if (cleanupSuccessful && cleanupMetadataCommitted) {
                    deleteAnchor(cleanupMetadataIdentity);
                }
                else {
                    deleteOwned(cleanupMetadataIdentity);
                }
            });
            cleanupFailure = cleanup(cleanupFailure, "pseudocode artifact", () -> {
                if (cleanupSuccessful && cleanupPseudocodeCommitted) {
                    deleteAnchor(cleanupPseudocodeIdentity);
                }
                else {
                    deleteOwned(cleanupPseudocodeIdentity);
                }
            });
            cleanupFailure = cleanup(cleanupFailure, "reservation", () ->
                deleteOwned(cleanupReservationIdentity));
            cleanupFailure = cleanup(cleanupFailure, "private stage", () ->
                deleteStage(cleanupStage));
            cleanupFailure = cleanup(cleanupFailure, "output identity", () ->
                deleteDirectoryIdentity(cleanupOutputIdentity));
            if (cleanupFailure != null) {
                if (primaryFailure != null) primaryFailure.addSuppressed(cleanupFailure);
                else throw cleanupFailure;
            }
        }
        println("wrote private shard " + start + "+" + count);
    }
}
