describe('Create and delete folder and file using cy.exec()', () => {
  it('should create a folder named mani and a file named mani.ts inside it', () => {
    // Create the folder
    cy.exec('mkdir -p mani').then((result) => {
      // Check the output to ensure the folder was created
      expect(result.code).to.equal(0);
    });

    // Create the file inside the folder
    cy.exec('touch mani/mani.ts').then((result) => {
      // Check the output to ensure the file was created
      expect(result.code).to.equal(0);
    });
  });

  it('should delete the folder named mani and the file named mani.ts inside it', () => {
    // Delete the folder and the file inside it
    cy.exec('rm -rf mani').then((result) => {
      // Check the output to ensure the folder and file were deleted
      expect(result.code).to.equal(0);
    });
  });
});
