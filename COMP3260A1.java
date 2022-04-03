//==============================================================================================
//COMP3260 Assignment 2 Group 18
//Harlan De Jong c3349828, Samuel Dolbel c
//This Program implements 4 different DES algorithms, It can encrypt according to DES0, DES1, DES2 and DES3
//It can decrypt according to DES0.
//For information to be encrypted, Plaintext and key (64 bit binary numbers) will be written in the local txt file "encrypt.txt", respectively
//For information to be decrypted, Ciphertext and key (64 bit binary numbers) will be written in the local txt file "decrypt.txt", respectively
//All outputs will be outputted via the console.
//The program also outputs the avalanche analysis of all multiple plaintext and multiple keys with respect to original plaintext and original key differing by 1 bit
//==============================================================================================

import java.io.File;  // Import the File class
import java.io.FileNotFoundException;  // Import this class to handle errors
import java.util.Scanner; // Import the Scanner class to read text files
import java.util.Arrays;
import java.util.ArrayList;
import java.io.*;
import java.util.*;

public class A2mostUpdated {
	public static int[][] textDesDiff = new int[17][4];//Global holds all different Des numbers (DES0-3) for all rounds
	public static int[][] keyDesDiff = new int[17][4];//Global holds all different key numbers for all rounds
	public static String outputStr;// Global holds the encrypted string for DES0

	public static void main(String[] args) {
		Date startTime = new Date();//record time
		String[] CodeAndKey = ReadFile("encrypt.txt");
		
		String pText = CodeAndKey[0];
		String Key = CodeAndKey[1];
		String[] Text = pText.split("");//string -> array
		String[] NewKey = Key.split("");

		WholeDES(Text, NewKey, 0, true);
		WholeDES(Text, NewKey, 1, true);
		WholeDES(Text, NewKey, 2, true);
		WholeDES(Text, NewKey, 3, true);
		
		WholeDES(Text, NewKey, 0, false);
		WholeDES(Text, NewKey, 1, false);
		WholeDES(Text, NewKey, 2, false);
		WholeDES(Text, NewKey, 3, false);

		Date endTime = new Date();
		EncryptionOutput(outputStr, Key, pText, (endTime.getTime() - startTime.getTime()), textDesDiff, keyDesDiff);
	
		CodeAndKey = ReadFile("decrypt.txt"); //all below is same as above just decryption
		
		pText = CodeAndKey[0];
		Key = CodeAndKey[1];
		Text = pText.split("");
		NewKey = Key.split("");

		String[] plain = DecryptDES(Text, NewKey);
		System.out.println("\n");
		DecryptionOutput(pText, Key, String.join("", plain));
	}

	public static String[] DecryptDES(String[] Text, String[] NewKey){ //function to decrypt given text with key according to DES0
		int i;
		String[][] K = findKeys(NewKey); //gets all 64 keys one bit differing from original key
    	String[] IPmessage = InitialPermutation(Text); //permutes Text according to IP table

		String[] Lim1 = new String[32];
		String[] Rim1 = new String[32];
		String[] Li = new String[32];
		String[] Ri = new String[32];

		for(i=0;i<=63;i++){
			if(i<32){
				Lim1[i] = IPmessage[i]; //initialising and splitting into L and R
			}
			else{
				Rim1[i-32] = IPmessage[i];
			}
		}


		String[] fOutput = new String[48];
		String[] Kn = new String[48];

		for(i=16;i>=1;i--){
			for(int j=0;j<=47;j++){//allocating the 2d array to 1d to work with
				Kn[j] = K[j][i-1];
			}
			Li = Rim1.clone(); //Li = Rim1

			fOutput = ExpansionPermutationE(Rim1); //using ExpansionPermutationE function
			fOutput = XOR(fOutput, Kn, 48); //XOR result of ExPermE with Kn

			String fOutputStr = String.join("", fOutput); //making it a string

			fOutput = SBoxes(fOutputStr); //Sbox function
			fOutput = PermutationFunction(fOutput); //Pfunction

			Ri = XOR(Lim1, fOutput, 32);
			Rim1 = Ri.clone();
			Lim1 = Li.clone();
		}

		String[] output = FinalPermutation(Switch(Li, Ri)); //doing last permutation and switch according to DES

		return output;
	}

	public static void WholeDES(String[] Text, String[] NewKey, int DESnumber, boolean IsTextShift){
		String[] firstPText = new String[64];
		String[] firstKey = new String[64];
		String[] firstCText = new String[64];
		String[][] pRoundOutput = new String[16][64];
		String[][] keyRoundOutput = new String[16][64];
		String[] output = new String[64];
		System.arraycopy(Text, 0, firstPText, 0, 64);
		System.arraycopy(NewKey, 0, firstKey, 0, 64);
		
		for (int index=-1; index<64; index++) {
			if (index > -1) {
				if (IsTextShift == true) {
					Text = Avalanche(firstPText, index);
				} else {
					NewKey = Avalanche(firstKey, index);
				}
			}

			// Round 0 text difference check
			for (int i=0; i<64; i++) {
				if (IsTextShift == true) {
					textDesDiff[0][DESnumber] = DifferentChar(Text[i], firstPText[i]);
				} else {
					keyDesDiff[0][DESnumber] = DifferentChar(Text[i], firstPText[i]);
				}
			}

			String[][] K = findKeys(NewKey);

			String[] IPmessage = InitialPermutation(Text);

			String[] Lim1 = LInitial(IPmessage);
			String[] Rim1 = RInitial(IPmessage);

			String[] Li = new String[32];
			String[] Ri = new String[32];

			String[] fOutput = new String[48];
			String[] Kn = new String[48];

			for(int i=1;i<=16;i++){
				for(int j=0;j<=47;j++){
					Kn[j] = K[j][i-1];
				}
				Li = Rim1.clone();

				if(DESnumber == 0){
					fOutput = Des0Encrypt(Rim1, Kn);
				}
				if(DESnumber == 1){
					fOutput = Des1Encrypt(Rim1, Kn);
				}
				if(DESnumber == 2){
					fOutput = Des2Encrypt(Rim1, Kn);
				}
				if(DESnumber == 3){
					fOutput = Des3Encrypt(Rim1, Kn);
				}

				Ri = XOR(Lim1, fOutput, 32);
				Rim1 = Ri.clone();
				Lim1 = Li.clone();
				
				int outputCount = 0;

				for (int k=0; k<Rim1.length; k++) {
					if (index == -1) {
						pRoundOutput[i-1][outputCount] = Rim1[k];
						outputCount++;
						pRoundOutput[i-1][outputCount] = Lim1[k];
						outputCount++;
					} else {
						if (IsTextShift == true) {
							textDesDiff[i][DESnumber] += DifferentChar(pRoundOutput[i-1][outputCount], Rim1[k]);
							outputCount++;

							textDesDiff[i][DESnumber] += DifferentChar(pRoundOutput[i-1][outputCount], Lim1[k]);
							outputCount++;
						} else {
							keyDesDiff[i][DESnumber] += DifferentChar(pRoundOutput[i-1][outputCount], Rim1[k]);
							outputCount++;

							keyDesDiff[i][DESnumber] += DifferentChar(pRoundOutput[i-1][outputCount], Lim1[k]);
							outputCount++;
						}
					}
				}
			}
			if(index == -1){
				firstCText = FinalPermutation(Switch(Li, Ri));
			}
		}
		if(DESnumber == 0){
			outputStr = String.join("", firstCText);
		}
	}


	public static String[] Avalanche(String[] input, int index) {
		String[] output = new String[64];

		for(int i=0;i<64;i++){
			output[i] = new String(input[i]);
		}

		if (output[index].equals("0")) {
			output[index] = "1";
		} else {
			output[index] = "0";
		}

		return output;
	}

	public static int DifferentChar(String char1, String char2) {
		if (char1.equals(char2)) {
			return 0;
		} else {
			return 1;
		}
	}

	public static String[] Des0Encrypt(String[] rim, String[] kn){
		String[] fOutput = ExpansionPermutationE(rim);

		fOutput = XOR(fOutput, kn, 48);

		String fOutputStr = String.join("", fOutput);

		fOutput = SBoxes(fOutputStr);
		fOutput = PermutationFunction(fOutput);

		return fOutput;
	}

	public static String[] Des1Encrypt(String[] rim, String[] kn){
		String[] fOutput = ExpansionPermutationE(rim);

		String fOutputStr = String.join("", fOutput);

		fOutput = SBoxes(fOutputStr);
		fOutput = PermutationFunction(fOutput);

		return fOutput;
	}

	public static String[] Des2Encrypt(String[] rim, String[] kn){
		String[] fOutput = ExpansionPermutationE(rim);
		fOutput = XOR(fOutput, kn, 48);

		fOutput = InverseExpansionPermutation(fOutput);
		fOutput = PermutationFunction(fOutput);

		return fOutput;
	}

	public static String[] Des3Encrypt(String[] rim, String[] kn){
		String[] fOutput = ExpansionPermutationE(rim);
		fOutput = XOR(fOutput, kn, 48);

		String fOutputStr = String.join("", fOutput);
		fOutput = SBoxes(fOutputStr);

		return fOutput;
	}

	public static String[] ReadFile(String filename){
		
		try{
			File myObj = new File(filename);
			Scanner reader = new Scanner(myObj);

			String[] CodeAndKey;
			CodeAndKey = new String[2];
			int i = 0;

			while(reader.hasNextLine()){
				String num = reader.nextLine();
				CodeAndKey[i] = num;
				i++;
			}
			reader.close();
			return CodeAndKey;
		}
		catch(FileNotFoundException e){
			System.out.println("File not found");
		}
		return null;
	}

	public static void EncryptionOutput(String cText, String key, String pText, Long time, int[][] textDiff, int[][] keyDiff) {
		System.out.println("ENCRYPTION");
		System.out.println("Plaintext P: " + pText);
		System.out.println("Key K: " + key);
		System.out.println("Ciphertext C: " + cText);
		System.out.println("Running time: " + time+"ms");

		System.out.print("\n\n");
		System.out.println("Avalanche:\n\n");
		System.out.println("P and Pi under K:");
		System.out.println("Round\t\tDES0\tDES1\tDES2\tDES3");

		for (int i=0; i<17; i++) {
			if (i > 0) {
				System.out.println(i+"\t\t"+textDiff[i][0]/64+"\t"+textDiff[i][1]/64+"\t"+textDiff[i][2]/64+"\t"+textDiff[i][3]/64);
			} else {
				System.out.println(i+"\t\t"+textDiff[i][0]+"\t"+textDiff[i][1]+"\t"+textDiff[i][2]+"\t"+textDiff[i][3]);
			}
		}

		System.out.print("\n\n");
		System.out.println("P under K and Ki:");
		System.out.println("Round\t\tDES0\tDES1\tDES2\tDES3");

		for (int i=0; i<17; i++) {
			if (i > 0) {
				System.out.println(i+"\t\t"+keyDiff[i][0]/64+"\t"+keyDiff[i][1]/64+"\t"+keyDiff[i][2]/64+"\t"+keyDiff[i][3]/64);
			} else {
				System.out.println(i+"\t\t"+keyDiff[i][0]+"\t"+keyDiff[i][1]+"\t"+keyDiff[i][2]+"\t"+keyDiff[i][3]);
			}
		}

	}

	public static void DecryptionOutput(String cText, String key, String pText) {
		System.out.println("DECRYPTION");
		System.out.println("Ciphertext C: " + cText);
		System.out.println("Key K: " + key);
		System.out.println("Plaintext P: " + pText);
	}

	public static String[] LInitial(String[] IPmessage){
		String[] Lim1 = new String[32];
		for(int i=0;i<32;i++){
			Lim1[i] = IPmessage[i];
		}
		return Lim1;
	}

	public static String[] RInitial(String[] IPmessage){
		String[] Rim1 = new String[32];
		for(int i=0;i<32;i++){
			Rim1[i] = IPmessage[i+32];
		}
		return Rim1;
	}

	public static String[] InitialPermutation(String[] Text){
		int[] IP = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
		String[] IPmessage = new String[64];

		for(int i=0;i<=63;i++){
			IPmessage[i] = Text[(IP[i])-1];
		}
		return IPmessage;
	}

	public static String[][] findKeys(String[] NewKey){
		int i=0;
		int[] PC1 = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
		int[] PC2 = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};

		String[] permute = new String[56];

		for(i=0;i<=55;i++){
			permute[i] = NewKey[(PC1[i])-1];
		}

		String[][] C = new String[28][17];
		String[][] D = new String[28][17];

		for(i=0;i<=55;i++){
			if(i<28){
				C[i][0] = permute[i];
			}
			else{
				D[i-28][0] = permute[i];
			}
		}
		
		for(i=1;i<=16;i++){
			if(i == 1 || i == 2 || i == 9 || i == 16){
				C = LShift(C, 1, i);
				D = LShift(D, 1, i);
			}
			else{
				C = LShift(C, 2, i);
				D = LShift(D, 2, i);
			}
		}

		String[][] CnDn = new String[56][16];

		for(i=0;i<=15;i++){
			for(int j=0;j<=55;j++){
				if(j<28){
					CnDn[j][i] = C[j][i+1];
				}
				else{
					CnDn[j][i] = D[j-28][i+1];
				}
			}
		}

		String[][] K = new String[48][16];

		for(i=0;i<=15;i++){
			for(int j=0;j<=47;j++){
				K[j][i] = CnDn[(PC2[j])-1][i];
			}
		}
		return K;
	}

	public static String[][] LShift(String[][] input, int shifts, int j){
		String temp;

		for(int i=0;i<shifts;i++){

			temp = input[0][j-1+i];

			for(int k=0;k<=26;k++){
				input[k][j] = input[k+1][j-1+i];
			}

			input[27][j] = temp;
		}
		return input; 
	}

	public static String[] ExpansionPermutationE(String[] input){
		int i=0;
		String[] output = new String[48];
		int[] E = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
		for(i=0;i<=47;i++){
			output[i] = input[(E[i])-1];
		}
		return output;
	}

	public static String[] XOR(String[] a, String[] b, int numBits){
		String[] result = new String[numBits];

		for(int i=0;i<numBits;i++){
			if(a[i].equalsIgnoreCase(b[i])){
				result[i] = "0";
			}
			else{
				result[i] = "1";
			}
		}
		return result;
	}

	public static String[] SBoxes(String input) {
		String temp = input;
		String sBoxOutput = "";

		int[][] SBox1 = {
			{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
			{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
			{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
			{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
		};
		int[][] SBox2 = {
			{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
			{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
			{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
		};
		int[][] SBox3 = {
			{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
			{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
			{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, 
			{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
		};
		int[][] SBox4 = {
			{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, 
			{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, 
			{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, 
			{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
		};
		int[][] SBox5 = {
			{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, 
			{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, 
			{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, 
			{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
		};
		int[][] SBox6 = {
			{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, 
			{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, 
			{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, 
			{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
		};
		int[][] SBox7 = {
			{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, 
			{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
			{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, 
			{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
		};
		int[][] SBox8 = {
			{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, 
			{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
			{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, 
			{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
		};
		
		int[][][] SBox = { SBox1, SBox2, SBox3, SBox4, SBox5, SBox6, SBox7, SBox8 };

		for (int i=0; i<8; i++) {
			String temp2 = temp.substring(i*6, ((i+1)*6));
			int[] coord = new int[2];
			coord[0] = BinaryToInt(temp2.substring(0, 1) + temp2.substring(5, 6));
			coord[1] = BinaryToInt(temp2.substring(1, 5));

			String temp3 = IntToBinary(SBox[i][coord[0]][coord[1]]);
			sBoxOutput = sBoxOutput + temp3;
		}
		String[] sBoxOutputArray = sBoxOutput.split("");

		return sBoxOutputArray;
	}

	public static String[] PermutationFunction(String[] input) {
		int[] P = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
		String[] Permuted = new String[32];

		for(int i=0;i<32;i++){
			Permuted[i] = input[(P[i])-1];
		}

		return Permuted;
	}

	public static String[] InverseExpansionPermutation(String[] input) {
		int[] E = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
		String[] Permuted = new String[32];

		for (int i=0; i<32; i++) {
			Permuted[i] = input[(E[i])-1];
		}

		return Permuted;
	}

	public static int BinaryToInt(String input) {
		String temp = input;
		int index = 1;
		int output = 0;

		do {
			output = output + index*(Integer.parseInt(temp.substring(temp.length()-1, temp.length())));
			temp = temp.substring(0, temp.length()-1);
			index *= 2;
		}
		while (temp.length() > 0);

		return output;
	}

	public static String IntToBinary(int input) {
		String intOutput = "";
		
		switch (input) {
			case 0:
			intOutput = "0000";
			break;
			case 1:
			intOutput = "0001";
			break;
			case 2:
			intOutput = "0010";
			break;
			case 3:
			intOutput = "0011";
			break;
			case 4:
			intOutput = "0100";
			break;
			case 5:
			intOutput = "0101";
			break;
			case 6:
			intOutput = "0110";
			break;
			case 7:
			intOutput = "0111";
			break;
			case 8:
			intOutput = "1000";
			break;
			case 9:
			intOutput = "1001";
			break;
			case 10:
			intOutput = "1010";
			break;
			case 11:
			intOutput = "1011";
			break;
			case 12:
			intOutput = "1100";
			break;
			case 13:
			intOutput = "1101";
			break;
			case 14:
			intOutput = "1110";
			break;
			case 15:
			intOutput = "1111";
			break;
		}

		return intOutput;
	}
	
	public static String[] Switch(String[] a, String[] b){
		String[] output = new String[64];
		for(int i=0;i<64;i++){
			if(i<32){
				output[i] = b[i];
			}
			else{
				output[i] = a[i-32];
			}
		}
		return output;
	}

	public static String[] FinalPermutation(String[] input){
		String[] output = new String[64];
		int[] IPm1 = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};

		for(int i=0;i<64;i++){
			output[i] = input[(IPm1[i])-1];
		}

		return output;
	}
}

